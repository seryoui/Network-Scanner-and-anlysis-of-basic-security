# NetScan Enterprise API Documentation

## Overview
NetScan Enterprise v2.0 is a professional-grade network intelligence and threat detection platform with enterprise security features.

## Authentication
All API endpoints require an API key passed via:
- Header: `X-API-Key: your_api_key`
- Query param: `?api_key=your_api_key`

## Endpoints

### Health & Info
- `GET /api/health` – Health check (no auth required)
- `GET /api/config` – Application configuration

### Network Scanning
- `GET /api/local-network` – Auto-detect local network
- `POST /api/scan` – Start network scan
  ```json
  {
    "network": "192.168.1.0/24",
    "ports": "80,443,22",
    "common_ports": false
  }
  ```
- `GET /api/results` – Get scan results
- `POST /api/stop` – Stop active scan

### Export & Reporting
- `GET /api/export/json` – Export as JSON
- `GET /api/export/csv` – Export as CSV
- `GET /api/export/txt` – Export as TXT
- `GET /api/export/html` – Export as HTML report

### Threat Detection
- `POST /api/yara-scan` – Scan content against malware signatures
  ```json
  {
    "content": "binary_or_text_content"
  }
  ```

### History & Analytics
- `GET /api/dashboard-stats` – User statistics
- `GET /api/history/scans` – Scan history
- `GET /api/history/threats` – Threat history
- `POST /api/history/clear` – Clear user history

### Audit
- `GET /api/audit-log` – View audit log

## Features

### New in v2.0
✅ API key authentication & rate limiting
✅ Comprehensive audit logging
✅ YARA-based threat detection
✅ HTML report export
✅ Multi-format export (JSON, CSV, TXT, HTML)
✅ Health checks & monitoring
✅ Production-ready security
✅ Concurrent scanning (100+ workers)
✅ Cross-platform support (Windows/Linux/Mac)
✅ Docker container support

## Rate Limiting
- General: 200 per day, 50 per hour
- Scans: 10 per hour
- Exports: 20 per hour
- Threat scans: 20 per hour

## Example Usage

### Start a scan
```bash
curl -X POST http://localhost:8080/api/scan \
  -H "X-API-Key: your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "network": "192.168.1.0/24",
    "common_ports": true
  }'
```

### Get results
```bash
curl http://localhost:8080/api/results \
  -H "X-API-Key: your_api_key"
```

### Export as HTML
```bash
curl http://localhost:8080/api/export/html \
  -H "X-API-Key: your_api_key" \
  -o report.html
```

### Scan for threats
```bash
curl -X POST http://localhost:8080/api/yara-scan \
  -H "X-API-Key: your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "suspicious_content_here"
  }'
```

## Configuration

Edit `config.json` to customize:
- API keys
- Max hosts per scan (default: 1024)
- Concurrent workers (default: 100)
- Rate limiting policies
- Timeout settings

## Logging

All actions logged to:
- `netscan.log` – Application logs
- `audit.log` – Audit trail (JSON format)

## Docker Deployment

### Development
```bash
docker compose up
```

### Production
```bash
docker compose --profile prod up -d
```

## Security Notes
- Always use HTTPS in production
- Rotate API keys regularly
- Monitor audit logs
- Use firewall rules to restrict access
- Run as non-root user (default in Docker)
- Enable rate limiting

## Version
NetScan Enterprise v2.0
