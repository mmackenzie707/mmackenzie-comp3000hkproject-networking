FROM python:3.11-slim

RUN pip install --no-cache-dir \
    torch \
    torchvision \
    numpy \
    scikit-learn

COPY ml-engine-module/ml_service.py /app/ml_service.py
COPY ml-engine-module/models/ /app/models/
COPY shared/ /app/shared/

WORKDIR /app
CMD ["python3", "ml_service.py"]