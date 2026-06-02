FROM python:3.11-slim

LABEL maintainer="NetScan Team"
LABEL version="2.0"
LABEL description="NetScan Enterprise - Professional Network Intelligence & Threat Detection"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    libyara-dev \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 netscan

# Set working directory
WORKDIR /app

# Copy requirements first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY --chown=netscan:netscan . .

# Switch to non-root user
USER netscan

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8080/api/health || exit 1

# Run app with production WSGI
CMD ["python", "-u", "app.py"]
