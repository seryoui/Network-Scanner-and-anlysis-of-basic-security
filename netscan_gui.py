import sys
import socket
import ipaddress
import concurrent.futures
import platform
import subprocess
import re
import os
import threading
import json
import csv
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox

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
        ttl_match = re.search(r"ttl=(\d+)", result.stdout, re.IGNORECASE)
        if ttl_match:
            return ip, int(ttl_match.group(1))
    except Exception:
        return None, None
    return None, None

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                return port
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
        os_name = get_os_from_ttl(ttl)
        open_ports_info = []
        if ports:
            for port in ports:
                port_result = scan_port(ip, port)
                if port_result:
                    open_ports_info.append(port_result)
        return ip, os_name, open_ports_info
    return None, None, []

class NetScanGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NetScan - Network Scanner")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        self.setup_style()
        self.create_widgets()
        
    def setup_style(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'))
        style.configure('Header.TLabel', font=('Arial', 10, 'bold'))
        style.configure('Normal.TLabel', font=('Arial', 9))
        style.configure('Action.TButton', font=('Arial', 9, 'bold'))
        style.configure('Success.TLabel', foreground='#2E7D32', font=('Arial', 9))
        style.configure('Error.TLabel', foreground='#C62828', font=('Arial', 9))
        
    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        title_label = ttk.Label(main_frame, text="NetScan - Network Scanner", style='Title.TLabel')
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 15))
        
        network_frame = ttk.LabelFrame(main_frame, text="Network Configuration", padding="10")
        network_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        network_frame.columnconfigure(1, weight=1)
        
        ttk.Label(network_frame, text="Network Range:", style='Header.TLabel').grid(row=0, column=0, sticky=tk.W, pady=2)
        
        self.network_var = tk.StringVar()
        self.network_entry = ttk.Entry(network_frame, textvariable=self.network_var, font=('Arial', 9))
        self.network_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=2)
        
        ttk.Button(network_frame, text="Detect Local", command=self.detect_local_network).grid(row=0, column=2, padx=(10, 0), pady=2)
        
        ports_frame = ttk.LabelFrame(main_frame, text="Port Scanning", padding="10")
        ports_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.port_scan_var = tk.BooleanVar(value=False)
        self.port_scan_check = ttk.Checkbutton(ports_frame, text="Enable Port Scanning", variable=self.port_scan_var, command=self.toggle_port_options)
        self.port_scan_check.grid(row=0, column=0, sticky=tk.W, pady=2)
        
        ttk.Label(ports_frame, text="Ports to scan:", style='Header.TLabel').grid(row=1, column=0, sticky=tk.W, pady=(10, 2))
        
        self.ports_mode_var = tk.StringVar(value="common")
        ports_mode_frame = ttk.Frame(ports_frame)
        ports_mode_frame.grid(row=1, column=1, sticky=tk.W, padx=(10, 0))
        
        ttk.Radiobutton(ports_mode_frame, text="Common Ports", variable=self.ports_mode_var, value="common").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(ports_mode_frame, text="Custom Ports", variable=self.ports_mode_var, value="custom").pack(side=tk.LEFT)
        
        self.custom_ports_var = tk.StringVar(value="80,443,22,21,3389")
        self.custom_ports_entry = ttk.Entry(ports_frame, textvariable=self.custom_ports_var, font=('Arial', 9))
        self.custom_ports_entry.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(5, 2))
        
        self.toggle_port_options()
        
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=(0, 10))
        
        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan, style='Action.TButton')
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_button = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(button_frame, text="Clear Results", command=self.clear_results).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Export Results", command=self.export_results).pack(side=tk.LEFT)
        
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        results_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding="10")
        results_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 5))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, font=('Consolas', 9))
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, style='Normal.TLabel', relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(5, 0))
        
        self.scan_thread = None
        self.scanning = False
        self.results = []
        
        self.detect_local_network()
        
    def toggle_port_options(self):
        if self.port_scan_var.get():
            self.custom_ports_entry.config(state=tk.NORMAL)
        else:
            self.custom_ports_entry.config(state=tk.DISABLED)
            
    def detect_local_network(self):
        try:
            ip, mask = get_local_ip_and_mask()
            cidr = mask_to_cidr(mask)
            network = f"{ip}/{cidr}"
            self.network_var.set(network)
            self.status_var.set(f"Local network detected: {network}")
        except Exception as e:
            self.status_var.set(f"Error detecting local network: {str(e)}")
            
    def start_scan(self):
        if self.scanning:
            return
            
        network_str = self.network_var.get().strip()
        if not network_str:
            messagebox.showerror("Error", "Please enter a network range")
            return
            
        try:
            self.network = parse_network(network_str)
        except Exception as e:
            messagebox.showerror("Error", f"Invalid network format: {str(e)}")
            return
            
        self.ports = None
        if self.port_scan_var.get():
            if self.ports_mode_var.get() == "common":
                self.ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389]
            else:
                try:
                    ports_str = self.custom_ports_var.get().strip()
                    self.ports = [int(p.strip()) for p in ports_str.split(',')]
                except ValueError:
                    messagebox.showerror("Error", "Invalid port format. Please use comma-separated numbers.")
                    return
                    
        self.scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.results = []
        self.results_text.delete(1.0, tk.END)
        self.progress.start()
        
        self.scan_thread = threading.Thread(target=self.run_scan)
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
    def stop_scan(self):
        self.scanning = False
        self.status_var.set("Stopping scan...")
        
    def clear_results(self):
        self.results = []
        self.results_text.delete(1.0, tk.END)
        self.status_var.set("Results cleared")
        
    def export_results(self):
        if not self.results:
            messagebox.showwarning("Warning", "No results to export")
            return
            
        filetypes = [
            ("Text files", "*.txt"),
            ("CSV files", "*.csv"),
            ("JSON files", "*.json"),
            ("All files", "*.*")
        ]
        
        filename = filedialog.asksaveasfilename(
            title="Export Results",
            defaultextension=".txt",
            filetypes=filetypes
        )
        
        if not filename:
            return
            
        try:
            if filename.endswith('.json'):
                with open(filename, 'w') as f:
                    json.dump({
                        "scan_date": datetime.now().isoformat(),
                        "network": str(self.network),
                        "results": self.results
                    }, f, indent=2)
            elif filename.endswith('.csv'):
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["IP Address", "OS", "Open Ports"])
                    for result in self.results:
                        ports_str = ', '.join(map(str, result['open_ports'])) if result['open_ports'] else ''
                        writer.writerow([result['ip'], result.get('os', 'Unknown'), ports_str])
            else:
                with open(filename, 'w') as f:
                    f.write(f"NetScan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Network: {self.network}\n")
                    f.write("=" * 60 + "\n\n")
                    for result in self.results:
                        f.write(f"Host: {result['ip']} ({result.get('os', 'Unknown')})\n")
                        if result['open_ports']:
                            f.write(f"  Open Ports: {', '.join(map(str, result['open_ports']))}\n")
                        f.write("\n")
                        
            self.status_var.set(f"Results exported to {os.path.basename(filename)}")
            messagebox.showinfo("Success", f"Results exported successfully to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export results: {str(e)}")
            
    def run_scan(self):
        try:
            self.root.after(0, lambda: self.status_var.set(f"Scanning network: {self.network}"))
            self.root.after(0, lambda: self.results_text.insert(tk.END, f"Scanning network: {self.network}\n"))
            if self.ports:
                self.root.after(0, lambda: self.results_text.insert(tk.END, f"Scanning ports: {', '.join(map(str, self.ports))}\n"))
            self.root.after(0, lambda: self.results_text.insert(tk.END, "-" * 60 + "\n\n"))
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                futures = {executor.submit(scan_host, str(ip), self.ports): ip for ip in self.network.hosts()}
                
                for future in concurrent.futures.as_completed(futures):
                    if not self.scanning:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                        
                    try:
                        host, os_name, open_ports = future.result()
                        if host:
                            result = {
                                "ip": host,
                                "os": os_name,
                                "open_ports": open_ports
                            }
                            self.results.append(result)
                            
                            self.root.after(0, lambda h=host, osn=os_name, op=open_ports: self.display_result(h, osn, op))
                    except Exception as e:
                        continue
                        
            self.results.sort(key=lambda x: tuple(map(int, x['ip'].split('.'))))
            
            self.root.after(0, lambda: self.progress.stop())
            self.root.after(0, lambda: self.scan_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.stop_button.config(state=tk.DISABLED))
            
            if self.scanning:
                self.root.after(0, lambda: self.status_var.set(f"Scan complete. Found {len(self.results)} online host(s)."))
            else:
                self.root.after(0, lambda: self.status_var.set(f"Scan stopped. Found {len(self.results)} online host(s)."))
                
        except Exception as e:
            self.root.after(0, lambda: self.progress.stop())
            self.root.after(0, lambda: self.scan_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.stop_button.config(state=tk.DISABLED))
            self.root.after(0, lambda: self.status_var.set(f"Error during scan: {str(e)}"))
            self.root.after(0, lambda: messagebox.showerror("Error", f"Scan failed: {str(e)}"))
        finally:
            self.scanning = False
            
    def display_result(self, host, os_name, open_ports):
        self.results_text.insert(tk.END, f"Host: {host} ({os_name})\n")
        if open_ports:
            self.results_text.insert(tk.END, f"  Open Ports: {', '.join(map(str, open_ports))}\n")
        self.results_text.insert(tk.END, "\n")
        self.results_text.see(tk.END)

def main():
    root = tk.Tk()
    app = NetScanGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
