FROM python:3.11-slim

# Install system dependencies for packet capture
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    net-tools \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Create directory for logs
RUN mkdir -p /var/log/firewall

# Set working directory
WORKDIR /app

# Copy requirements and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY *.py ./
COPY rules.json ./

# Make the script executable
RUN chmod +x firewall.py

# Create non-root user (though we need privileged mode for packet capture)
RUN useradd -m -u 1000 firewalluser

# Set entrypoint
ENTRYPOINT ["python3", "firewall.py"]