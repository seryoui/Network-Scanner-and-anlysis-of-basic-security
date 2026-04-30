# for coomad-line arguments and exiting
import sys
# for networking interface and ip oprations
import socket
# for ip network calculations
import ipaddress
# for parallel thread execution
import concurrent.futures
# for detecting operation system
import platform
# for running os commands
import subprocess
# for regular expressions
import re
# for possible future os operations
import os

# =================================================================================================================
def print_app_name():
    print("""
_   _      _    _____
| \\ | |    | |  / ____|
|  \\| | ___| |_| (___   ___ __ _ _ __
| . ` |/ _ \\ __|\\___ \\ / __/ _` | '_ \\
| |\\  |  __/ |_ ____) | (_| (_| | | | |
|_| \\_|\\___|\\__|_____/ \\___\\__,_|_| |_|

Welcome to NetScan, a network scanner brought to you by >>> Synerdyn <<<
for business inquiries contact by email to : business@synerdyn.net

        """)
# =================================================================================================================


# =================================================================================================================
def get_local_ip_and_mask():
    """
    Detects the local IP address and subnet mask from the system.
    Works for both Windows and Unix-like systems.
    """
    system = platform.system().lower() # detect the os type
    if system == 'windows':
        output = subprocess.check_output("ipconfig", universal_newlines=True)  # Run ipconfig and get output
        ip_match = re.search(r'IPv4 Address[. ]*: ([\d.]+)', output)           # Find the IPv4 address
        mask_match = re.search(r'Subnet Mask[. ]*: ([\d.]+)', output)          # Find the subnet mask
        if ip_match and mask_match:
            return ip_match.group(1), mask_match.group(1)                      # Return IP and mask if found
    else:
        # For Linux/macOS, use ifconfig and parse output
        output = subprocess.check_output("ifconfig", shell=True, universal_newlines=True)
        ip_match = re.search(r'inet ([\d.]+).*?netmask (0x[\da-f]+|[\d.]+)', output)
        if ip_match:
            ip = ip_match.group(1)                                             # Extract IP address
            mask = ip_match.group(2)                                           # Extract netmask
            if mask.startswith("0x"):                                          # If netmask is in hex
                mask = socket.inet_ntoa(int(mask,16).to_bytes(4, "big"))       # Convert hex to dotted decimal
            return ip, mask
    # Fallback: Try to infer IP, assume /24 mask
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))                                             # Dummy connect to get local IP
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip, '255.255.255.0'                                                 # Default mask
# =================================================================================================================


# =================================================================================================================
def mask_to_cidr(mask):
    """
    Converts a dotted-decimal subnet mask (e.g., 255.255.255.0) to CIDR notation (e.g., 24).
    """
    return sum(bin(int(x)).count('1') for x in mask.split('.'))
# =================================================================================================================


# =================================================================================================================
def parse_network(arg=None):
    """
    Parses the network argument and returns an ipaddress.ip_network object.
    Handles no argument (auto-detect), /24, /16, etc.
    """
    if not arg:
        ip, mask = get_local_ip_and_mask()                                     # Get local IP and mask
        cidr = mask_to_cidr(mask)                                              # Convert mask to CIDR
        return ipaddress.ip_network(f"{ip}/{cidr}", strict=False)              # Create network object
    if '/' in arg:
        return ipaddress.ip_network(arg, strict=False)                         # User provided CIDR
    elif re.match(r'^\d+\.\d+\.\d+$', arg):
        return ipaddress.ip_network(arg + '.0/24', strict=False)               # e.g., 192.168.1 → 192.168.1.0/24
    elif re.match(r'^\d+\.\d+\.\d+\.\d+$', arg):
        return ipaddress.ip_network(arg + '/24', strict=False)                 # e.g., 192.168.1.5 → 192.168.1.5/24
    else:
        raise ValueError("Invalid network format")                             # Invalid input

# =================================================================================================================

# =================================================================================================================
def ping(ip):
    """
    Pings a single IP address.
    Returns the IP if online (responds to ping), otherwise None.
    """
    ip = str(ip)                                                               # Ensure IP is string
    system = platform.system().lower()                                         # Detect OS
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "1000", ip]                            # Windows: 1 ping, 1s timeout
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]                               # Unix: 1 ping, 1s timeout
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
        if re.search(r"ttl", result.stdout, re.IGNORECASE):                    # "ttl" in output = host responded
            return ip
    except subprocess.TimeoutExpired:
        return None                                                            # Timed out, host not online
    except Exception:
        return None                                                            # Other error, treat as offline
# =================================================================================================================


# =================================================================================================================
def scan_network(network):
    """
    Scans all hosts in the given network in parallel.
    Returns a list of online hosts.
    """
    print(f"Scanning network: {network}")                                      # Inform user what is being scanned
    online = []                                                                # List to store online hosts
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:   # Use 100 threads
            futures = {executor.submit(ping, ip): ip for ip in network.hosts()}   # Submit ping jobs
            for future in concurrent.futures.as_completed(futures):                # As each finishes
                try:
                    result = future.result()                                       # Get result
                    if result:
                        online.append(result)                                      # Add if online
                except Exception:
                    continue                                                       # Ignore errors
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Showing results so far...")         # Handle Ctrl+C gracefully
    return online
# =====================================================================================================ne============


# =================================================================================================================
def show_help():
    """
    Prints usage and help information.
    """
    print(
        "Usage: netscan [network]\n"
        "Scan a network for online devices.\n\n"
        "Options:\n"
        "  -h, --help     Show this help message\n"
        "Examples:\n"
        "  netscan                 # Scan current local network\n"
        "  netscan 192.168.1.0     # Scan 192.168.1.0/24\n"
        "  netscan 192.168.1       # Scan 192.168.1.0/24\n"
        "  netscan 192.168.1.0/24  # Scan 192.168.1.0/24"
    )
# =================================================================================================================


# =================================================================================================================
# MAIN
# =================================================================================================================
def main():
    """
    Main function: parses arguments, runs scan, prints results.
    """
    args = sys.argv[1:]                                                        # Get command-line arguments
    if not args:
        try:
            network = parse_network()                                          # No arg: auto-detect local network
        except Exception as e:
            print(f"Error: {e}")
            show_help()
            return
    elif args[0] in ['-h', '--help']:
        show_help()                                                            # Show help if -h/--help
        return
    elif len(args) == 1:
        try:
            network = parse_network(args[0])                                   # Parse provided network arg
        except Exception as e:
            print(f"Error: {e}")
            show_help()
            return
    else:
        show_help()                                                            # Too many args: show help
        return

    try:
        online_hosts = scan_network(network)                                   # Scan the network
        print("\nOnline hosts:")                                               # Print header
        for host in sorted(online_hosts, key=lambda x: tuple(map(int, x.split('.')))):
            print(host)                                                        # Print each online host
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")                                   # Handle Ctrl+C again

if __name__ == "__main__":
    main()