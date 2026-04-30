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
    Returns the IP if online (responds to ping), otherwise None.
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
            return ip
    except Exception:
        return None
    return None

def scan_port(ip, port):
    """
    Checks if a specific TCP port is open on an IP.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                return port
    except Exception:
        pass
    return None

def scan_host(ip, ports=None):
    """
    Scans a host for online status and optionally scans ports.
    """
    if ping(ip):
        open_ports = []
        if ports:
            for port in ports:
                if scan_port(ip, port):
                    open_ports.append(port)
        return ip, open_ports
    return None, []

def scan_network(network, ports=None):
    """
    Scans all hosts in the given network in parallel.
    Returns a list of tuples (host, open_ports).
    """
    print(f"Scanning network: {network}")
    if ports:
        print(f"Scanning ports: {', '.join(map(str, ports))}")
    
    results = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(scan_host, str(ip), ports): ip for ip in network.hosts()}
            for future in concurrent.futures.as_completed(futures):
                try:
                    host, open_ports = future.result()
                    if host:
                        results.append((host, open_ports))
                except Exception:
                    continue
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Showing results so far...")
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
    """
    Main function: parses arguments, runs scan, prints results.
    """
    print_app_name()
    args = sys.argv[1:]
    
    ports = None
    network_arg = None
    
    # Simple argument parsing
    i = 0
    while i < len(args):
        if args[i] in ['-h', '--help']:
            show_help()
            return
        elif args[i] in ['-p', '--ports']:
            if i + 1 < len(args):
                p_arg = args[i+1]
                if p_arg.lower() == 'common':
                    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389]
                else:
                    try:
                        ports = [int(p.strip()) for p in p_arg.split(',')]
                    except ValueError:
                        print(f"Error: Invalid ports format: {p_arg}")
                        return
                i += 1
            else:
                print("Error: -p/--ports requires an argument")
                return
        else:
            network_arg = args[i]
        i += 1

    try:
        network = parse_network(network_arg)
    except Exception as e:
        print(f"Error: {e}")
        show_help()
        return

    try:
        results = scan_network(network, ports)
        print("\nScan Results:")
        # Sort results by IP address
        results.sort(key=lambda x: tuple(map(int, x[0].split('.'))))
        
        for host, open_ports in results:
            if ports:
                ports_str = f" [Open ports: {', '.join(map(str, open_ports)) if open_ports else 'none found'}]"
                print(f"{host}{ports_str}")
            else:
                print(host)
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")

if __name__ == "__main__":
    main()
