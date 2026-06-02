"""
NetScan Enterprise - Professional Network Intelligence & Threat Detection
Version: 2.0
Description: Enterprise-grade network reconnaissance, threat detection, and compliance reporting
"""

import sys
import socket
import ipaddress
import concurrent.futures
import platform
import subprocess
import re
import os
import threading
import logging
import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from functools import wraps

from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import csv
import json
from io import StringIO, BytesIO
import yara

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('netscan.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# FLASK APP INITIALIZATION
# ============================================================================
app = Flask(__name__)
CORS(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Configuration
app.config['JSON_SORT_KEYS'] = False
HISTORY_FILE = 'scan_history.json'
CONFIG_FILE = 'config.json'
AUDIT_LOG = 'audit.log'

# ============================================================================
# SECURITY & AUTHENTICATION
# ============================================================================
class SecurityManager:
    """Manages API key validation, rate limiting, and audit logging"""
    
    def __init__(self):
        self.valid_api_keys = self._load_api_keys()
    
    def _load_api_keys(self) -> List[str]:
        """Load API keys from config or environment"""
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                return config.get('api_keys', [])
        except:
            return []
    
    def validate_api_key(self, api_key: str) -> bool:
        """Validate incoming API key"""
        return api_key in self.valid_api_keys or api_key == os.getenv('ADMIN_API_KEY', '')
    
    def audit_log(self, user: str, action: str, status: str, details: str = ""):
        """Log all significant actions for compliance"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'user': user,
            'action': action,
            'status': status,
            'details': details,
            'ip': request.remote_addr if request else 'N/A'
        }
        try:
            with open(AUDIT_LOG, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.error(f"Audit log write failed: {e}")

security = SecurityManager()

def require_auth(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if not api_key or not security.validate_api_key(api_key):
            security.audit_log('unknown', f.__name__, 'FAILED', 'Invalid API key')
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

# ============================================================================
# DATA MANAGEMENT
# ============================================================================
def get_current_user() -> str:
    """Extract user from request headers or API key"""
    return request.headers.get('X-User', request.headers.get('X-API-Key', 'anonymous')[:8])

def load_history() -> Dict:
    """Load scan and threat history"""
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading history: {e}")
    return {"scans": [], "threats": [], "metadata": {"version": "2.0"}}

def save_history(history: Dict) -> None:
    """Save scan and threat history with backup"""
    try:
        # Create backup before saving
        if os.path.exists(HISTORY_FILE):
            backup_name = f"{HISTORY_FILE}.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            os.rename(HISTORY_FILE, backup_name)
        
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        logger.error(f"Error saving history: {e}")

def get_config() -> Dict:
    """Load application configuration"""
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except:
        return {
            'api_keys': [],
            'max_hosts_per_scan': 1024,
            'max_ports_per_host': 100,
            'scan_timeout': 300,
            'concurrent_workers': 100
        }

# ============================================================================
# YARA THREAT ENGINE
# ============================================================================
class ThreatDetectionEngine:
    """YARA-based malware and payload detection"""
    
    def __init__(self):
        self.rules = self._load_rules()
        self.detections_cache = {}
    
    def _load_rules(self) -> Optional[yara.Rules]:
        """Load and compile YARA rules"""
        try:
            sig_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'signatures.yar')
            if os.path.exists(sig_path):
                rules = yara.compile(filepath=sig_path)
                logger.info(f"YARA rules loaded successfully from {sig_path}")
                return rules
            else:
                logger.warning(f"YARA rules file not found at {sig_path}")
                return None
        except Exception as e:
            logger.error(f"Error compiling YARA rules: {e}")
            return None
    
    def scan(self, content: bytes) -> List[Dict]:
        """Scan content against YARA rules"""
        if not self.rules:
            return []
        
        try:
            matches = self.rules.match(data=content)
            results = []
            for match in matches:
                results.append({
                    'rule': match.rule,
                    'tags': list(match.tags),
                    'description': match.meta.get('description', 'N/A'),
                    'severity': match.meta.get('severity', 'unknown').upper(),
                    'timestamp': datetime.now().isoformat()
                })
            return results
        except Exception as e:
            logger.error(f"YARA scan error: {e}")
            return []

threat_engine = ThreatDetectionEngine()

# ============================================================================
# NETWORK SCANNING CORE
# ============================================================================
class NetworkScanner:
    """Core network scanning and host discovery"""
    
    def __init__(self):
        self.config = get_config()
    
    def get_local_ip_and_mask(self) -> Tuple[str, str]:
        """Detect local IP and subnet mask (cross-platform)"""
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
        
        # Fallback: detect via DNS
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('8.8.8.8', 80))
                ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        
        return ip, '255.255.255.0'
    
    @staticmethod
    def mask_to_cidr(mask: str) -> int:
        """Convert subnet mask to CIDR notation"""
        return sum(bin(int(x)).count('1') for x in mask.split('.'))
    
    def parse_network(self, arg: Optional[str] = None) -> ipaddress.IPv4Network:
        """Parse network argument (CIDR, IP/mask, or auto-detect)"""
        if not arg:
            ip, mask = self.get_local_ip_and_mask()
            cidr = self.mask_to_cidr(mask)
            return ipaddress.ip_network(f"{ip}/{cidr}", strict=False)
        
        if '/' in arg:
            return ipaddress.ip_network(arg, strict=False)
        elif re.match(r'^\d+\.\d+\.\d+$', arg):
            return ipaddress.ip_network(arg + '.0/24', strict=False)
        elif re.match(r'^\d+\.\d+\.\d+\.\d+$', arg):
            return ipaddress.ip_network(arg + '/24', strict=False)
        else:
            raise ValueError("Invalid network format. Use CIDR (192.168.1.0/24) or IP (192.168.1.1)")
    
    @staticmethod
    def ping(ip: str) -> Tuple[Optional[str], Optional[int]]:
        """Ping host and extract TTL for OS detection"""
        system = platform.system().lower()
        
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", "1000", str(ip)]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", str(ip)]
        
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
            if re.search(r"ttl", result.stdout, re.IGNORECASE):
                ttl_match = re.search(r"ttl=(\d+)", result.stdout, re.IGNORECASE)
                ttl = int(ttl_match.group(1)) if ttl_match else None
                return str(ip), ttl
        except Exception as e:
            logger.debug(f"Ping error for {ip}: {e}")
        
        return None, None
    
    @staticmethod
    def grab_banner(ip: str, port: int) -> str:
        """Grab service banner for port identification"""
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
    
    @staticmethod
    def scan_port(ip: str, port: int) -> Optional[Dict]:
        """Scan single port"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0:
                    banner = NetworkScanner.grab_banner(ip, port)
                    return {"port": port, "banner": banner}
        except Exception:
            pass
        return None
    
    @staticmethod
    def get_os_from_ttl(ttl: Optional[int]) -> str:
        """Detect OS from TTL value"""
        if ttl is None:
            return "Unknown"
        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "Solaris/Cisco"
        return "Unknown"
    
    @staticmethod
    def get_arp_table() -> Dict[str, str]:
        """Fetch MAC addresses from ARP table"""
        try:
            output = subprocess.check_output("arp -a", shell=True, universal_newlines=True)
            matches = re.findall(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})', output)
            return {ip: mac.replace('-', ':').lower() for ip, mac in matches}
        except Exception as e:
            logger.debug(f"ARP table fetch error: {e}")
            return {}
    
    def scan_host(self, ip: str, ports: Optional[List[int]] = None) -> Tuple[Optional[str], Optional[str], str, List[Dict]]:
        """Scan single host"""
        online_ip, ttl = self.ping(ip)
        if not online_ip:
            return None, None, "", []
        
        # Reverse DNS
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = "Unknown Host"
        
        os_name = self.get_os_from_ttl(ttl)
        
        open_ports_info = []
        if ports:
            for port in ports:
                port_result = self.scan_port(ip, port)
                if port_result:
                    open_ports_info.append(port_result)
        
        return online_ip, hostname, os_name, open_ports_info
    
    def run_scan(self, network: ipaddress.IPv4Network, ports: Optional[List[int]], user: str) -> List[Dict]:
        """Execute full network scan with concurrency"""
        logger.info(f"Starting scan on {network} by user {user}")
        scan_results = []
        
        try:
            host_list = []
            max_hosts = self.config.get('max_hosts_per_scan', 1024)
            
            for i, ip in enumerate(network.hosts()):
                if i >= max_hosts:
                    break
                host_list.append(ip)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.get('concurrent_workers', 100)) as executor:
                futures = {executor.submit(self.scan_host, str(ip), ports): ip for ip in host_list}
                
                for future in concurrent.futures.as_completed(futures):
                    try:
                        host, hostname, os_name, open_ports = future.result()
                        if host:
                            arp_table = self.get_arp_table()
                            mac = arp_table.get(host, "Unknown MAC")
                            
                            scan_results.append({
                                'ip': host,
                                'hostname': hostname,
                                'mac': mac,
                                'os': os_name,
                                'open_ports': open_ports
                            })
                    except Exception as e:
                        logger.error(f"Host scan error: {e}")
            
            scan_results.sort(key=lambda x: tuple(map(int, x['ip'].split('.'))) if x['ip'] else (0,0,0,0))
            logger.info(f"Scan complete. Found {len(scan_results)} active hosts.")
            
        except Exception as e:
            logger.error(f"Scan thread error: {e}")
        
        return scan_results

scanner = NetworkScanner()

# ============================================================================
# GLOBAL STATE (Thread-safe scanning)
# ============================================================================
scan_results = []
scan_lock = threading.Lock()
scanning_event = threading.Event()
current_scan_id = None

# ============================================================================
# API ROUTES
# ============================================================================

@app.route('/')
def index():
    """Serve main dashboard"""
    return render_template('index.html')

@app.route('/api/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': '2.0',
        'timestamp': datetime.now().isoformat()
    }), 200

@app.route('/api/config')
@limiter.limit("10 per minute")
def get_app_config():
    """Get application configuration (public)"""
    config = get_config()
    return jsonify({
        'max_hosts_per_scan': config.get('max_hosts_per_scan'),
        'concurrent_workers': config.get('concurrent_workers'),
        'common_ports': [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389]
    }), 200

@app.route('/api/local-network')
@limiter.limit("20 per minute")
def get_local_network():
    """Auto-detect local network"""
    try:
        ip, mask = scanner.get_local_ip_and_mask()
        cidr = scanner.mask_to_cidr(mask)
        return jsonify({
            'ip': ip,
            'mask': mask,
            'network': f"{ip}/{cidr}",
            'timestamp': datetime.now().isoformat()
        }), 200
    except Exception as e:
        logger.error(f"Local network detection error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan', methods=['POST'])
@limiter.limit("10 per hour")
def start_scan():
    """Start network scan (requires auth)"""
    global scan_results, current_scan_id
    
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
            network = scanner.parse_network(network_str)
        except Exception as e:
            return jsonify({'error': f'Invalid network format: {str(e)}'}), 400
        
        ports = None
        if scan_common_ports:
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389]
        elif ports_str:
            try:
                ports = [int(p.strip()) for p in ports_str.split(',') if p.strip()]
                if len(ports) > get_config().get('max_ports_per_host', 100):
                    return jsonify({'error': f"Too many ports (max {get_config().get('max_ports_per_host')})"}), 400
            except ValueError:
                return jsonify({'error': 'Invalid port format'}), 400
        
        scanning_event.set()
        current_scan_id = str(uuid.uuid4())
        user = get_current_user()
        
        scan_thread = threading.Thread(target=lambda: execute_scan(network, ports, user, current_scan_id))
        scan_thread.daemon = True
        scan_thread.start()
        
        security.audit_log(user, 'start_scan', 'SUCCESS', f"Network: {network}")
        
        return jsonify({
            'status': 'started',
            'scan_id': current_scan_id,
            'network': str(network),
            'timestamp': datetime.now().isoformat()
        }), 200
    
    except Exception as e:
        logger.error(f"Scan start error: {e}")
        return jsonify({'error': f'Internal error: {str(e)}'}), 500

def execute_scan(network, ports, user, scan_id):
    """Execute scan in background thread"""
    global scan_results
    
    with scan_lock:
        scan_results = []
    
    try:
        results = scanner.run_scan(network, ports, user)
        
        with scan_lock:
            scan_results = results
        
        # Save to history
        history = load_history()
        history['scans'].append({
            'scan_id': scan_id,
            'user': user,
            'timestamp': datetime.now().isoformat(),
            'network': str(network),
            'hosts_found': len(results),
            'results': results
        })
        history['scans'] = history['scans'][-100:]
        save_history(history)
        
        security.audit_log(user, 'scan_complete', 'SUCCESS', f"Found {len(results)} hosts")
    
    except Exception as e:
        logger.error(f"Scan execution error: {e}")
        security.audit_log(user, 'scan_complete', 'FAILED', str(e))
    
    finally:
        scanning_event.clear()

@app.route('/api/results')
@limiter.limit("30 per minute")
def get_results():
    """Get current scan results"""
    with scan_lock:
        return jsonify({
            'results': list(scan_results),
            'scanning': scanning_event.is_set(),
            'scan_id': current_scan_id,
            'timestamp': datetime.now().isoformat()
        }), 200

@app.route('/api/stop', methods=['POST'])
@limiter.limit("10 per minute")
def stop_scan():
    """Stop active scan"""
    user = get_current_user()
    scanning_event.clear()
    security.audit_log(user, 'stop_scan', 'SUCCESS', '')
    return jsonify({'status': 'stopped', 'timestamp': datetime.now().isoformat()}), 200

@app.route('/api/export/<export_format>')
@limiter.limit("20 per hour")
def export_results(export_format):
    """Export scan results in multiple formats"""
    user = get_current_user()
    
    with scan_lock:
        results = list(scan_results)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if export_format == 'json':
        security.audit_log(user, 'export', 'SUCCESS', f'format={export_format}')
        return jsonify({
            'scan_date': datetime.now().isoformat(),
            'host_count': len(results),
            'results': results
        }), 200
    
    elif export_format == 'csv':
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["IP Address", "Hostname", "MAC Address", "OS", "Open Ports"])
        
        for result in results:
            ports_str = '; '.join([f"{p['port']}({p['banner']})" for p in result['open_ports']]) if result['open_ports'] else 'None'
            writer.writerow([result['ip'], result['hostname'], result['mac'], result.get('os', 'Unknown'), ports_str])
        
        output.seek(0)
        security.audit_log(user, 'export', 'SUCCESS', f'format={export_format}')
        
        return send_file(
            BytesIO(output.getvalue().encode()),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'netscan_results_{timestamp}.csv'
        )
    
    elif export_format == 'txt':
        output = StringIO()
        output.write(f"NetScan Enterprise Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        output.write("=" * 80 + "\n\n")
        
        for result in results:
            output.write(f"Host: {result['ip']} ({result['hostname']})\n")
            output.write(f"  MAC Address: {result['mac']}\n")
            output.write(f"  Operating System: {result.get('os', 'Unknown')}\n")
            if result['open_ports']:
                ports_str = ', '.join([f"{p['port']}[{p['banner']}]" for p in result['open_ports']])
                output.write(f"  Open Ports: {ports_str}\n")
            output.write("-" * 80 + "\n")
        
        output.seek(0)
        security.audit_log(user, 'export', 'SUCCESS', f'format={export_format}')
        
        return send_file(
            BytesIO(output.getvalue().encode()),
            mimetype='text/plain',
            as_attachment=True,
            download_name=f'netscan_results_{timestamp}.txt'
        )
    
    elif export_format == 'html':
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>NetScan Results</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .header {{ background-color: #333; color: white; padding: 15px; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>NetScan Enterprise - Network Scan Report</h1>
        <p>Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Total Hosts Found: {len(results)}</p>
    </div>
    <table>
        <tr>
            <th>IP Address</th>
            <th>Hostname</th>
            <th>MAC Address</th>
            <th>Operating System</th>
            <th>Open Ports</th>
        </tr>
"""
        for result in results:
            ports_str = '; '.join([f"{p['port']} ({p['banner']})" for p in result['open_ports']]) if result['open_ports'] else 'None'
            html_content += f"""
        <tr>
            <td>{result['ip']}</td>
            <td>{result['hostname']}</td>
            <td>{result['mac']}</td>
            <td>{result.get('os', 'Unknown')}</td>
            <td>{ports_str}</td>
        </tr>
"""
        html_content += """
    </table>
</body>
</html>
"""
        security.audit_log(user, 'export', 'SUCCESS', f'format={export_format}')
        
        return send_file(
            BytesIO(html_content.encode()),
            mimetype='text/html',
            as_attachment=True,
            download_name=f'netscan_results_{timestamp}.html'
        )
    
    return jsonify({'error': 'Invalid format'}), 400

@app.route('/api/yara-scan', methods=['POST'])
@limiter.limit("20 per hour")
def yara_scan():
    """Scan content against YARA threat signatures"""
    user = get_current_user()
    
    try:
        data = request.get_json()
        content = data.get('content', '')
        
        if not content:
            return jsonify({'error': 'Content is required'}), 400
        
        matches = threat_engine.scan(content.encode() if isinstance(content, str) else content)
        
        if matches:
            history = load_history()
            history['threats'].append({
                'timestamp': datetime.now().isoformat(),
                'user': user,
                'matches': matches,
                'content_preview': content[:100] + '...' if len(content) > 100 else content
            })
            history['threats'] = history['threats'][-100:]
            save_history(history)
            security.audit_log(user, 'threat_detected', 'SUCCESS', f"Found {len(matches)} matches")
        
        return jsonify({
            'matches': matches,
            'count': len(matches),
            'timestamp': datetime.now().isoformat()
        }), 200
    
    except Exception as e:
        logger.error(f"YARA scan error: {e}")
        security.audit_log(user, 'yara_scan', 'FAILED', str(e))
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard-stats')
@limiter.limit("30 per minute")
def get_dashboard_stats():
    """Get dashboard statistics"""
    user = get_current_user()
    history = load_history()
    
    user_scans = [s for s in history['scans'] if s.get('user') == user]
    user_threats = [t for t in history['threats'] if t.get('user') == user]
    
    total_scans = len(user_scans)
    total_hosts = sum(s['hosts_found'] for s in user_scans)
    total_threats = len(user_threats)
    
    port_dist = {}
    for scan in user_scans:
        for res in scan.get('results', []):
            for port_info in res.get('open_ports', []):
                port = str(port_info['port'])
                port_dist[port] = port_dist.get(port, 0) + 1
    
    top_ports = dict(sorted(port_dist.items(), key=lambda item: item[1], reverse=True)[:5])
    
    return jsonify({
        'total_scans': total_scans,
        'total_hosts': total_hosts,
        'total_threats': total_threats,
        'top_ports': top_ports,
        'recent_scans': user_scans[-5:][::-1],
        'timestamp': datetime.now().isoformat()
    }), 200

@app.route('/api/history/scans')
@limiter.limit("20 per minute")
def get_scan_history():
    """Get scan history"""
    user = get_current_user()
    history = load_history()
    user_scans = [s for s in history['scans'] if s.get('user') == user]
    
    return jsonify({
        'scans': user_scans[-20:],
        'total': len(user_scans),
        'timestamp': datetime.now().isoformat()
    }), 200

@app.route('/api/history/threats')
@limiter.limit("20 per minute")
def get_threat_history():
    """Get threat detection history"""
    user = get_current_user()
    history = load_history()
    user_threats = [t for t in history['threats'] if t.get('user') == user]
    
    return jsonify({
        'threats': user_threats[-20:],
        'total': len(user_threats),
        'timestamp': datetime.now().isoformat()
    }), 200

@app.route('/api/history/clear', methods=['POST'])
@limiter.limit("5 per hour")
def clear_history():
    """Clear user history"""
    user = get_current_user()
    save_history({"scans": [], "threats": [], "metadata": {"version": "2.0"}})
    security.audit_log(user, 'clear_history', 'SUCCESS', '')
    return jsonify({'status': 'history cleared', 'timestamp': datetime.now().isoformat()}), 200

@app.route('/api/audit-log')
@limiter.limit("10 per minute")
def get_audit_log():
    """Get audit log (admin only)"""
    user = get_current_user()
    
    if not os.path.exists(AUDIT_LOG):
        return jsonify({'logs': [], 'count': 0}), 200
    
    try:
        with open(AUDIT_LOG, 'r') as f:
            logs = [json.loads(line) for line in f.readlines()[-100:]]
        return jsonify({'logs': logs, 'count': len(logs)}), 200
    except Exception as e:
        logger.error(f"Audit log read error: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

# ============================================================================
# APPLICATION START
# ============================================================================

if __name__ == '__main__':
    logger.info("=" * 80)
    logger.info("NetScan Enterprise v2.0 - Starting")
    logger.info(f"Starting server on http://0.0.0.0:8080")
    logger.info("=" * 80)
    
    app.run(host='0.0.0.0', port=8080, debug=False, threaded=True)
