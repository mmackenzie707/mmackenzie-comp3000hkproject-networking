FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    iptables \
    && rm -rf /var/lib/apt/lists/*

COPY action-module/action_service.py /app/action_service.py
COPY shared/ /app/shared/

WORKDIR /app
CMD ["python3", "action_service.py"]