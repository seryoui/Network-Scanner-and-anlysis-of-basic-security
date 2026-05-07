# NetScan - Network Scanner

A fast network scanner with both CLI and GUI interfaces.

## Features

### 🔍 Network Scanner (Python)
- **Network discovery**: Fast ICMP-based host discovery
- **Port scanning**: TCP port scanning with common ports preset
- **GUI interface**: User-friendly Tkinter GUI
- **CLI interface**: Command-line version for scripting
- **Export capabilities**: Save results in TXT, CSV, or JSON format

## Installation

### Prerequisites
- **Python 3.7+**

### Setup
```bash
# No installation required - just run the Python scripts
python netscan.py --help
python netscan_gui.py
```

## Usage

### GUI Version
```bash
python netscan_gui.py
```
The GUI provides:
- Auto-detect local network
- Custom network range input
- Port scanning options
- Real-time results display
- Results export (TXT, CSV, JSON)

### CLI Version
```bash
# Scan local network
python netscan.py

# Scan specific network
python netscan.py 192.168.1.0/24

# With port scanning
python netscan.py 192.168.1.0/24 -p 80,443,22

# Scan common ports
python netscan.py 192.168.1.0/24 --ports common
```

#### CLI Options
```
-h, --help              Show help
-p, --ports PORTS       Comma-separated list of ports or "common"
                        Common ports: 21,22,23,25,53,80,110,135,139,443,445,3389
```

## Project Structure
```
project/
├── netscan.py                # Network scanner CLI
├── netscan_gui.py            # Network scanner GUI
└── README.md                 # This file
```

## Examples

### Scanning a Network
```bash
# Scan local network for devices with open common ports
python netscan.py --ports common
```

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## License
This project is provided for educational and research purposes only.

## Disclaimer
This tool is intended for authorized security testing and research purposes only. The authors are not responsible for any misuse or damage caused by this tool.
