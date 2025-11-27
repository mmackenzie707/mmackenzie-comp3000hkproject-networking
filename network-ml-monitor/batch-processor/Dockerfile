FROM python:3.11-slim

# Install iptables for IP blocking
RUN apt-get update && apt-get install -y \
    iptables \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install ML dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy processor code
COPY main.py /app/
COPY threat_detection.py /app/

# Create directories
RUN mkdir -p /app/logs /app/models /app/config

# Run as root (required for iptables)
USER root

CMD ["python", "main.py"]