FROM python:3.11-slim

# Install network tools
RUN apt-get update && apt-get install -y \
    tcpdump \
    libpcap-dev \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy sniffer code
COPY packet-sniffer.py /app/

# Create logs directory
RUN mkdir -p /app/logs

# Run as root (required for packet capture)
USER root

CMD ["python", "packet-sniffer.py"]