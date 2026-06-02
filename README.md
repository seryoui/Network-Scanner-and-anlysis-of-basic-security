# NetScan - README

## Overview
**NetScan** is a professional-grade network intelligence platform with:
- Advanced network discovery & OS fingerprinting
- Multi-threaded concurrent scanning (100+ hosts)
- YARA-based malware & payload detection
- API key authentication & rate limiting
- Comprehensive audit logging
- Multi-format reporting (JSON, CSV, TXT, HTML)

## Quick Start

### Docker (Recommended)
```bash
# Development
docker compose up

# Production
export ADMIN_API_KEY="your_secure_key_here"
docker compose --profile prod up -d
```

### Local Setup
```bash
pip install -r requirements.txt
python app.py
```

Access: `http://localhost:8080`

## API Key Setup
Edit `config.json` and add your API keys:
```json
{
  "api_keys": [
    "your_api_key_here",
    "another_key_here"
  ]
}
```

## Usage

### Start a Scan
```bash
curl -X POST http://localhost:8080/api/scan \
  -H "X-API-Key: your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "network": "192.168.1.0/24",
    "common_ports": true
  }'
```

### Get Results
```bash
curl http://localhost:8080/api/results \
  -H "X-API-Key: your_api_key"
```

### Export Report
```bash
curl http://localhost:8080/api/export/html \
  -H "X-API-Key: your_api_key" \
  -o report.html
```

See `API_DOCS.md` for full documentation.

## Features

### Network Scanning
- 🎯 Host discovery via ICMP ping
- 🔍 Port scanning (TCP connect)
- 🏷️ Service banner grabbing
- 🖥️ OS detection (TTL analysis)
- 🔗 Reverse DNS lookup
- 🔄 MAC address resolution (ARP)
- ⚡ Concurrent scanning (100 workers)

### Threat Detection
- 🛡️ YARA-based malware scanning
- ⚠️ Real-time threat alerts
- 📊 Threat statistics
- 📜 Threat history tracking

### Reporting & Export
- 📄 HTML professional reports
- 📊 JSON export
- 📈 CSV spreadsheets
- 📝 Plain text reports

### Security & Compliance
- 🔐 API key authentication
- 🚦 Rate limiting per endpoint
- 📋 Comprehensive audit logs
- 👤 Per-user history
- 🔒 Non-root Docker container

## Configuration

### config.json
```json
{
  "api_keys": ["your_keys_here"],
  "max_hosts_per_scan": 1024,
  "max_ports_per_host": 100,
  "concurrent_workers": 100,
  "rate_limiting": {
    "daily": 200,
    "hourly": 50
  }
}
```

### Environment Variables
```bash
export ADMIN_API_KEY="your_key"
export FLASK_ENV="production"
export LOG_LEVEL="WARNING"
```

## Logs
- `netscan.log` – Application logs
- `audit.log` – Audit trail (JSON)
- `docker logs netscan-enterprise` – Container logs

## File Structure
```
netscan-app/
├── app.py                  # Main application (v2.0 Enterprise)
├── web_app.py             # Legacy v1 (in archive/)
├── config.json            # Configuration
├── requirements.txt       # Python dependencies
├── Dockerfile             # Container image
├── docker-compose.yml     # Local development
├── templates/             # Web UI templates
├── API_DOCS.md           # API documentation
├── UPGRADE.md            # Migration guide
├── archive/              # Previous versions
└── README.md             # This file
```

## Requirements
- Python 3.9+
- Docker (recommended)
- Flask 2.0+
- yara-python 4.5+

## Performance
- Scans up to 1024 hosts concurrently
- 0.5s timeout per port
- 2s timeout per host
- Optimized for networks up to /20 (4096 hosts)

## Security Notes
✅ API key validation on all endpoints
✅ Rate limiting enabled
✅ Audit logging for compliance
✅ Non-root container user
✅ Input validation
✅ CORS enabled for web UI
✅ Health checks integrated

⚠️ Security Recommendations:
- Always use HTTPS in production
- Rotate API keys regularly
- Monitor audit logs
- Use firewall rules
- Keep Python/Docker updated

## Upgrading from v1
See `UPGRADE.md` for detailed migration instructions.

## Support & Documentation
- `API_DOCS.md` – Complete API reference
- `UPGRADE.md` – Migration from v1
- `netscan.log` – Application logs
- `audit.log` – Security audit trail

## License
NetScan Enterprise v2.0

## Version
2.0.0

## Status
✅ Production Ready
