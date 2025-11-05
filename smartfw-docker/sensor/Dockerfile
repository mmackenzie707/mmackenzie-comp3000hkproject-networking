FROM python:3.11-slim-bookworm
RUN apt-get update && apt-get install -y iptables iproute2 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ .
USER 1000
CMD [ "gunicorn", "-b", "0.0.0.0:5000", "cli:main" ]