FROM python:3.11

# Install only runtime dependencies (no build tools needed for pure Python)
RUN apt-get update && apt-get install -y \
    tcpdump \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash firewalluser && \
    mkdir -p /app/logs && \
    chown -R firewalluser:firewalluser /app

WORKDIR /app

# Copy pre-downloaded packages
COPY packages/ /packages/

# Install Python packages offline
RUN pip install --no-index --find-links=/packages scapy psutil

# Clean up packages
RUN rm -rf /packages

# Copy application code
COPY --chown=firewalluser:firewalluser *.py ./
COPY --chown=firewalluser:firewalluser rules.json ./

# Fix permissions
RUN chmod 755 /app/logs

USER firewalluser
ENTRYPOINT ["python3", "firewall.py"]