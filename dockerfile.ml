FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install fastapi uvicorn scikit-learn pandas numpy joblib
COPY . .
CMD ["uvicorn", "ml_service:app", "--host", "0.0.0.0", "--port", "8000"]