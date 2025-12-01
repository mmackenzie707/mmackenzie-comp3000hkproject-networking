FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY preprocessing-module/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY preprocessing-module/preprocessing_service.py /app/preprocessing_service.py
COPY shared/ /app/shared/

WORKDIR /app
CMD ["python3", "preprocessing_service.py"]