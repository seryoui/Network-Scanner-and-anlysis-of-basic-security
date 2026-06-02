import sys
import socket
import ipaddress
import concurrent.futures
import platform
import subprocess
import re
import os

def print_app_name():
    print("""
   _   _      _    _____                
  | \\ | |    | |  / ____|                
  |  \\| | ___| |_| (___   ___ __ _ _ __   
  | . ` |/ _ \\ __|\\___ \\ / __/ _` | '_ \\ 
  | |\\  |  __/ |_ ____) | (_| (_| | | | | 
  |_| \\_|\\___|\\__|_____/ \\___\\__,_|_| |_| 
                                         
 Welcome to NetScan, a network scanner
                                         
           """)

def get_local_ip_and_mask():
    """
    Detects the local IP address and subnet mask from the system.
    Works for both Windows and Unix-like systems.
    """
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
    
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip, '255.255.255.0'

def mask_to_cidr(mask):
    """
    Converts a dotted-decimal subnet mask (e.g., 255.255.255.0) to CIDR notation (e.g., 24).
    """
    return sum(bin(int(x)).count('1') for x in mask.split('.'))

def parse_network(arg=None):
    """
    Parses the network argument and returns an ipaddress.ip_network object.
    """
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
    """
    Pings a single IP address.
    Returns (ip, ttl) if online, otherwise (None, None).
    """
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
    except Exception:
        return None, None
    return None, None

def grab_banner(ip, port):
    """
    Attempts to grab a service banner from an open port.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            s.connect((ip, port))
            # Some services require a probe to send a banner
            if port == 80:
                s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            elif port == 443:
                # SSL/TLS would need a wrapper, keeping it simple for now
                return "HTTPS (SSL/TLS)"
            
            banner = s.recv(1024).decode(errors='ignore').strip()
            if banner:
                # Clean up the banner (take first line, remove non-printable)
                banner = banner.split('\n')[0].strip()
                return banner[:50] # Limit length
    except Exception:
        pass
    return "Unknown Service"

def scan_port(ip, port):
    """
    Checks if a specific TCP port is open on an IP.
    Returns (port, banner) if open, otherwise None.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                banner = grab_banner(ip, port)
                return port, banner
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
    """
    Scans a host for online status and optionally scans ports.
    """
    online_ip, ttl = ping(ip)
    if online_ip:
        os_name = get_os_from_ttl(ttl)
        open_ports_info = []
        if ports:
            for port in ports:
                port_result = scan_port(ip, port)
                if port_result:
                    open_ports_info.append(port_result)
        return ip, os_name, open_ports_info
    return None, None, []

def get_arp_table():
    """
    Retrieves the ARP table from the system.
    """
    try:
        output = subprocess.check_output("arp -a", shell=True, universal_newlines=True)
        # Regex to find IP and MAC addresses
        # Windows format: 192.168.1.1       00-11-22-33-44-55     dynamic
        # Unix format: ? (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0
        matches = re.findall(r'(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F:-]{12,17})', output)
        return {ip: mac for ip, mac in matches}
    except Exception:
        return {}

def scan_network(network, ports=None):
    """
    Scans all hosts in the given network in parallel.
    Returns a list of tuples (host, open_ports_info).
    """
    print(f"Scanning network: {network}")
    if ports:
        print(f"Scanning ports: {', '.join(map(str, ports))}")
    
    # Try to get ARP table for faster/more reliable local discovery
    arp_table = get_arp_table()
    
    results = []
    # Use ThreadPoolExecutor for concurrent scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        # Create a list of futures
        futures = {executor.submit(scan_host, str(ip), ports): ip for ip in network.hosts()}
        
        for future in concurrent.futures.as_completed(futures):
            try:
                host, os_name, open_ports = future.result()
                if host:
                    mac = arp_table.get(host, "Unknown MAC")
                    results.append({
                        'ip': host,
                        'mac': mac,
                        'os': os_name,
                        'ports': open_ports
                    })
                    print(f"[+] Found host: {host} ({mac}) - OS: {os_name}")
                    for p, b in open_ports:
                        print(f"    - Port {p}: {b}")
            except Exception as e:
                pass
    
    return results

def show_help():
    """
    Prints usage and help information.
    """
    print(
        "Usage: netscan [network] [options]\n"
        "Scan a network for online devices and open ports.\n\n"
        "Options:\n"
        "  -h, --help           Show this help message\n"
        "  -p, --ports PORTS    Comma-separated list of ports to scan (e.g., 80,443)\n"
        "                       Use 'common' for 21,22,23,25,53,80,110,135,139,443,445,3389\n\n"
        "Examples:\n"
        "  netscan                 # Scan current local network\n"
        "  netscan 192.168.1.0 -p 80,443\n"
        "  netscan 192.168.1.0/24 --ports common"
    )

def main():
    import argparse
    parser = argparse.ArgumentParser(description="NetScan - Basic Network Scanner")
    parser.add_argument("network", nargs="?", help="Network to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("--ports", help="Comma-separated list of ports to scan, or 'common'")
    
    args = parser.parse_args()
    
    print_app_name()
    
    try:
        network = parse_network(args.network)
    except Exception as e:
        print(f"Error: {e}")
        return

    ports = None
    if args.ports == "common":
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389]
    elif args.ports:
        ports = [int(p.strip()) for p in args.ports.split(",")]
    
    results = scan_network(network, ports)
    
    print("\nScan Summary:")
    print("-" * 30)
    print(f"Hosts found: {len(results)}")
    for res in results:
        print(f"IP: {res['ip']} ({res['mac']}) - OS: {res['os']}")
        if res['ports']:
            print(f"  Ports: {', '.join([str(p) for p, b in res['ports']])}")
    print("-" * 30)

if __name__ == "__main__":
    main()
