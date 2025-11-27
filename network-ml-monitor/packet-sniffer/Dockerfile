FROM python:3.11-slim

# Install network tools
RUN apk add --no-cache \
    tcpdump \
    libpcap-dev \
    sqlite

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