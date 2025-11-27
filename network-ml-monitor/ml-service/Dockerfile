FROM python:3.11-apline

# Install minimal runtime dependencies (no build-essential needed)
RUN apt-get update && apt-get install -y \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . /app/
RUN mkdir -p /app/models /app/logs /app/config

CMD ["python", "main.py"]