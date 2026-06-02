import sys
import socket
import ipaddress
import concurrent.futures
import platform
import subprocess
import re
import os
import threading
import random
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
import csv
import json
from io import StringIO, BytesIO
import yara

app = Flask(__name__)

HISTORY_FILE = 'scan_history.json'

def get_current_user():
    return request.headers.get('X-User', 'anonymous')

def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading history: {e}")
    return {"scans": [], "threats": []}

def save_history(history):
    try:
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=4)
    except Exception as e:
        print(f"Error saving history: {e}")

# Compile YARA rules
try:
    # Get absolute path to the signatures file
    sig_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'signatures.yar')
    if os.path.exists(sig_path):
        yara_rules = yara.compile(filepath=sig_path)
        print(f"YARA rules loaded successfully from {sig_path}")
    else:
        print(f"YARA rules file not found at {sig_path}")
        yara_rules = None
except Exception as e:
    print(f"Error compiling YARA rules: {e}")
    yara_rules = None

def get_local_ip_and_mask():
    system = platform.system().lower()
    if system == 'windows':
        try:
            output = subprocess.check_output("ipconfig", universal_newlines=True)
            ip_match = re.search(r'IPv4 Address[. ]*: ([\d.]+)', output)
            mask_match = re.search(r'Subnet Mask[. ]*: ([\d.]+)', output)
            if ip_match and mask_match:
                return ip_match.group(1), mask_match.group(1)
        except Exception:
            pass
    else:
        try:
            output = subprocess.check_output("ifconfig", shell=True, universal_newlines=True)
            ip_match = re.search(r'inet ([\d.]+).*?netmask (0x[\da-f]+|[\d.]+)', output)
            if ip_match:
                ip = ip_match.group(1)
                mask = ip_match.group(2)
                if mask.startswith("0x"):
                    mask = socket.inet_ntoa(int(mask, 16).to_bytes(4, "big"))
                return ip, mask
        except Exception:
            pass
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    return ip, '255.255.255.0'

def mask_to_cidr(mask):
    return sum(bin(int(x)).count('1') for x in mask.split('.'))

def parse_network(arg=None):
    if not arg:
        ip, mask = get_local_ip_and_mask()
        cidr = mask_to_cidr(mask)
        return ipaddress.ip_network(f"{ip}/{cidr}", strict=False)
    if '/' in arg:
        return ipaddress.ip_network(arg, strict=False)
    elif re.match(r'^\d+\.\d+\.\d+$', arg):
        return ipaddress.ip_network(arg + '.0/24', strict=False)
    elif re.match(r'^\d+\.\d+\.\d+\.\d+$', arg):
        return ipaddress.ip_network(arg + '/24', strict=False)
    else:
        raise ValueError("Invalid network format")

def ping(ip):
    ip = str(ip)
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
        if re.search(r"ttl", result.stdout, re.IGNORECASE):
            ttl_match = re.search(r"ttl=(\d+)", result.stdout, re.IGNORECASE)
            ttl = int(ttl_match.group(1)) if ttl_match else None
            return ip, ttl
    except Exception as e:
        print(f"Ping error for {ip}: {e}")
        return None, None
    return None, None

def grab_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            s.connect((ip, port))
            if port == 80:
                s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            elif port == 443:
                return "HTTPS (SSL/TLS)"
            
            data = s.recv(1024)
            if not data:
                return "Open (No Banner)"
                
            banner = data.decode(errors='ignore').strip().split('\n')[0][:50]
            return banner if banner else "Open"
    except Exception:
        return "Open"

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                banner = grab_banner(ip, port)
                return {"port": port, "banner": banner}
    except Exception:
        pass
    return None

def get_os_from_ttl(ttl):
    if ttl is None:
        return "Unknown"
    if ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Solaris/Cisco"
    return "Unknown"

def scan_host(ip, ports=None):
    online_ip, ttl = ping(ip)
    if online_ip:
        # Add Reverse DNS Lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = "Unknown Host"
            
        os_name = get_os_from_ttl(ttl)
            
        open_ports_info = []
        if ports:
            for port in ports:
                port_result = scan_port(ip, port)
                if port_result:
                    open_ports_info.append(port_result)
        return ip, hostname, os_name, open_ports_info
    return None, None, None, []

scan_results = []
scan_lock = threading.Lock()
scanning_event = threading.Event()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/local-network')
def get_local_network():
    try:
        ip, mask = get_local_ip_and_mask()
        cidr = mask_to_cidr(mask)
        return jsonify({
            'ip': ip,
            'mask': mask,
            'network': f"{ip}/{cidr}"
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan', methods=['POST'])
def start_scan():
    global scan_results
    
    if scanning_event.is_set():
        return jsonify({'error': 'A scan is already in progress'}), 400
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
            
        network_str = data.get('network', '')
        ports_str = data.get('ports', '')
        scan_common_ports = data.get('common_ports', False)
        
        if not network_str:
            return jsonify({'error': 'Network range is required'}), 400
        
        try:
            network = parse_network(network_str)
        except Exception as e:
            return jsonify({'error': f'Invalid network format: {str(e)}'}), 400
        
        ports = None
        if scan_common_ports:
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389]
        elif ports_str:
            try:
                ports = [int(p.strip()) for p in ports_str.split(',') if p.strip()]
            except ValueError:
                return jsonify({'error': 'Invalid port format. Use comma-separated numbers.'}), 400
        
        scanning_event.set()
        # The actual scan results are cleared in run_scan thread to avoid race conditions
        
        user = get_current_user()
        scan_thread = threading.Thread(target=run_scan, args=(network, ports, user))
        scan_thread.daemon = True
        scan_thread.start()
        
        return jsonify({'status': 'started', 'network': str(network)})
    except Exception as e:
        print(f"Error starting scan: {e}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

def get_arp_table():
    try:
        # Use arp -a and handle different output formats
        output = subprocess.check_output("arp -a", shell=True, universal_newlines=True)
        # Match IP addresses and MAC addresses
        # Improved regex to handle various spacing and formats
        matches = re.findall(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})', output)
        return {ip: mac.replace('-', ':').lower() for ip, mac in matches}
    except Exception as e:
        print(f"ARP table fetch error: {e}")
        return {}

def run_scan(network, ports, user):
    global scan_results
    print(f"Starting scan on network: {network}")
    
    with scan_lock:
        scan_results = []
        
    try:
        host_list = []
        for i, ip in enumerate(network.hosts()):
            if not scanning_event.is_set(): break
            if i >= 1024: break
            host_list.append(ip)

        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(scan_host, str(ip), ports): ip for ip in host_list}
            
            for future in concurrent.futures.as_completed(futures):
                if not scanning_event.is_set(): 
                    # Cancel pending futures if scan is stopped
                    for f in futures:
                        if not f.done():
                            f.cancel()
                    break
                try:
                    host, hostname, os_name, open_ports = future.result()
                    if host:
                        # Fetch ARP table once per discovery batch or every few hosts
                        # to balance speed and accuracy
                        arp_table = get_arp_table()
                        mac = arp_table.get(host, "Unknown MAC")
                        
                        with scan_lock:
                            scan_results.append({
                                'ip': host,
                                'hostname': hostname,
                                'mac': mac,
                                'os': os_name,
                                'open_ports': open_ports
                            })
                except Exception as e:
                    continue
                    
        with scan_lock:
            scan_results.sort(key=lambda x: tuple(map(int, x['ip'].split('.'))) if x['ip'] else (0,0,0,0))
            
            # Save to history with user association
            if scan_results:
                history = load_history()
                history['scans'].append({
                    'user': user,
                    'timestamp': datetime.now().isoformat(),
                    'network': str(network),
                    'hosts_found': len(scan_results),
                    'results': scan_results
                })
                # Keep only last 100 scans total
                history['scans'] = history['scans'][-100:]
                save_history(history)
    except Exception as e:
        print(f"Scan thread error: {e}")
    finally:
        scanning_event.clear()

@app.route('/api/results')
def get_results():
    with scan_lock:
        return jsonify({
            'results': list(scan_results),
            'scanning': scanning_event.is_set()
        })

@app.route('/api/stop', methods=['POST'])
def stop_scan():
    scanning_event.clear()
    return jsonify({'status': 'stopped'})

@app.route('/api/export/<format>')
def export_results(format):
    user = get_current_user()
    with scan_lock:
        # Currently, scan_results is a global for the active scan. 
        # For a truly per-user experience, we would need to track active scans per user.
        # For now, we filter the current active scan if needed, or assume the user
        # only exports their own active scan.
        results = list(scan_results)
    
    if format == 'json':
        return jsonify({
            'scan_date': datetime.now().isoformat(),
            'results': results
        })
    
    elif format == 'csv':
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["IP Address", "Hostname", "MAC Address", "OS", "Open Ports"])
        for result in results:
            ports_str = '; '.join([f"{p['port']}({p['banner']})" for p in result['open_ports']]) if result['open_ports'] else 'None'
            writer.writerow([result['ip'], result['hostname'], result['mac'], result.get('os', 'Unknown'), ports_str])
        
        output.seek(0)
        return send_file(
            BytesIO(output.getvalue().encode()),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'netscan_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        )
    
    elif format == 'txt':
        output = StringIO()
        output.write(f"NetScan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        output.write("=" * 60 + "\n\n")
        for result in results:
            output.write(f"Host: {result['ip']} ({result['hostname']})\n")
            output.write(f"  MAC: {result['mac']}\n")
            output.write(f"  OS: {result.get('os', 'Unknown')}\n")
            if result['open_ports']:
                ports_str = ', '.join([f"{p['port']}[{p['banner']}]" for p in result['open_ports']])
                output.write(f"  Open Ports: {ports_str}\n")
            output.write("-" * 30 + "\n")
        
        output.seek(0)
        return send_file(
            BytesIO(output.getvalue().encode()),
            mimetype='text/plain',
            as_attachment=True,
            download_name=f'netscan_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
        )
    
    return jsonify({'error': 'Invalid format'}), 400

@app.route('/api/yara-scan', methods=['POST'])
def yara_scan():
    if not yara_rules:
        return jsonify({'error': 'YARA rules not loaded'}), 500
    
    try:
        data = request.get_json()
        content = data.get('content', '')
        if not content:
            return jsonify({'error': 'Content is required'}), 400
        
        # Scan content (handle both string and bytes)
        matches = yara_rules.match(data=content.encode() if isinstance(content, str) else content)
        
        result = []
        for match in matches:
            result.append({
                'rule': match.rule,
                'description': match.meta.get('description', '')
            })
        
        # Save threat to history with user association
        if result:
            user = get_current_user()
            history = load_history()
            history['threats'].append({
                'user': user,
                'timestamp': datetime.now().isoformat(),
                'matches': result,
                'content_preview': content[:100] + '...' if len(content) > 100 else content
            })
            history['threats'] = history['threats'][-100:]
            save_history(history)
            
        return jsonify({'matches': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard-stats')
def get_dashboard_stats():
    user = get_current_user()
    history = load_history()
    
    # Filter by user
    user_scans = [s for s in history['scans'] if s.get('user') == user]
    user_threats = [t for t in history['threats'] if t.get('user') == user]
    
    total_scans = len(user_scans)
    total_hosts = sum(s['hosts_found'] for s in user_scans)
    total_threats = len(user_threats)
    
    # Port Distribution
    port_dist = {}
    for scan in user_scans:
        for res in scan['results']:
            for port_info in res.get('open_ports', []):
                port = str(port_info['port'])
                port_dist[port] = port_dist.get(port, 0) + 1
    
    # Get top 5 ports
    top_ports = dict(sorted(port_dist.items(), key=lambda item: item[1], reverse=True)[:5])

    return jsonify({
        'total_scans': total_scans,
        'total_hosts': total_hosts,
        'total_threats': total_threats,
        'top_ports': top_ports,
        'recent_scans': user_scans[-5:][::-1] # Last 5 scans, newest first
    })

@app.route('/api/history/clear', methods=['POST'])
def clear_history():
    save_history({"scans": [], "threats": []})
    return jsonify({'status': 'history cleared'})

if __name__ == '__main__':
    print("Starting NetScan server on http://0.0.0.0:8080")
    app.run(host='0.0.0.0', port=8080, debug=False)
