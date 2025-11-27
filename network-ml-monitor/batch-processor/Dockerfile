FROM python:3.11-alpine

# Fix DNS issues at build time
RUN echo "deb http://mirrors.cloud.google.com/debian bookworm main" > /etc/apt/sources.list && \
    echo "deb http://mirrors.cloud.google.com/debian bookworm-updates main" >> /etc/apt/sources.list && \
    echo "deb http://mirrors.cloud.google.com/debian-security bookworm-security main" >> /etc/apt/sources.list
    
# Install system packages (iptables, sqlite)
RUN apt-get update && apt-get install -y \
    iptables \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy code
COPY main.py /app/
COPY threat_detection.py /app/

# Create directories
RUN mkdir -p /app/logs /app/models /app/config

# No need for USER root - already root by default

CMD ["python", "main.py"]