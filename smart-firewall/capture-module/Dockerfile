FROM ubuntu:22.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    snort \
    python3 \
    python3-pip \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Create capture directory with correct permissions
RUN mkdir -p /data/captures && chmod 777 /data/captures

# Copy clean config with NO invalid syntax
COPY capture-module/snort_flow_capture.conf /etc/snort/
COPY capture-module/local.rules /etc/snort/rules/

# Copy service code
COPY capture-module/capture_service.py /app/capture_service.py
COPY shared/ /app/shared/

WORKDIR /app
CMD ["python3", "capture_service.py"]