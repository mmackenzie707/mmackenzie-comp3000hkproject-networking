FROM python:3.11-slim

COPY orchestrator/main_orchestrator.py /app/main_orchestrator.py
COPY shared/ /app/shared/

WORKDIR /app
CMD ["python3", "main_orchestrator.py"]