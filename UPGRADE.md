# NetScan Enterprise v2.0 - Upgrade Guide

## What's New

### Security Enhancements
- **API Key Authentication** – All endpoints now require API key validation
- **Rate Limiting** – Per-endpoint rate limits (10-30 requests/minute)
- **Audit Logging** – Complete action trail (audit.log)
- **Non-root Docker** – Runs as unprivileged netscan user
- **Health Checks** – Built-in container health monitoring

### New Features
- **HTML Report Export** – Professional formatted reports
- **Threat Detection Engine** – Improved YARA scanning with metadata
- **Scan IDs** – Track scans with unique UUIDs
- **Dashboard Statistics** – Enhanced metrics
- **Configurable Limits** – Max hosts, ports, workers (config.json)
- **Improved Error Handling** – Detailed error messages
- **Production WSGI** – Ready for load balancers

### Code Quality
- **Structured Classes** – NetworkScanner, ThreatDetectionEngine, SecurityManager
- **Type Hints** – Full typing for IDE support
- **Comprehensive Logging** – DEBUG, INFO, ERROR levels
- **Error Handlers** – 404, 500 status pages
- **Thread Safety** – Improved locking mechanisms

## Migration from v1

### 1. Update Dependencies
```bash
pip install -r requirements.txt  # Now includes flask-cors, flask-limiter
```

### 2. Generate API Keys
```bash
# Edit config.json and add your API keys
ADMIN_API_KEY=your_secure_key_here docker compose up
```

### 3. Update Requests
Old: `curl http://localhost:8080/api/scan`
New: `curl -H "X-API-Key: your_key" http://localhost:8080/api/scan`

### 4. Old Endpoint Changes
- Web app renamed: `web_app.py` → `app.py`
- New health endpoint: `GET /api/health`
- Results now include: `scan_id`, `timestamp`

### 5. New Config File
Copy template:
```bash
cp config.json.example config.json
# Edit with your API keys and limits
```

## Running v2.0

### Development
```bash
docker compose up
# Access: http://localhost:8080
# API Key required in headers
```

### Production
```bash
export ADMIN_API_KEY="your_strong_key_here"
docker compose --profile prod up -d
```

### Local (No Docker)
```bash
pip install -r requirements.txt
python app.py
# Start scanning with valid API key
```

## Features Removed
- ✗ `netscan.py` (GUI app) – Moved to archive/
- ✗ `netscan_gui.py` – Use web UI instead

## Features Preserved
- ✓ Network scanning (ping, port scan, OS detection)
- ✓ ARP-based MAC address resolution
- ✓ Banner grabbing
- ✓ Reverse DNS lookup
- ✓ Multi-format export (CSV, JSON, TXT + new HTML)
- ✓ YARA threat detection
- ✓ Scan history
- ✓ Cross-platform (Windows/Linux/Mac)

## Backward Compatibility
- Old `web_app.py` preserved in `archive/` folder
- Database format unchanged (scan_history.json)
- Port 8080 unchanged
- API endpoints mostly compatible (auth added)

## Performance
- Faster concurrent scanning (100 workers)
- Better memory management
- Improved error recovery
- Reduced CPU usage under load

## Monitoring

### Check Logs
```bash
docker logs netscan-enterprise
tail -f netscan.log
```

### Audit Trail
```bash
tail -f audit.log | jq .
```

### Health Check
```bash
curl http://localhost:8080/api/health
```

## Troubleshooting

### API Key Rejected
- Check header: `X-API-Key: your_key`
- Verify key exists in `config.json`
- Check `audit.log` for auth failures

### Rate Limited
- Wait 1 hour or adjust limits in `config.json`
- Check `X-RateLimit-*` headers in response

### Scans Not Working
- Ensure network format valid: `192.168.1.0/24` or `192.168.1.1`
- Check `netscan.log` for network errors
- Verify sufficient permissions (ping, arp)

## Support
See `API_DOCS.md` for full endpoint documentation
