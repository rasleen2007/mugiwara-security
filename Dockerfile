FROM python:3.12-slim

WORKDIR /app

COPY setup.py .
COPY src/ src/
COPY requirements-cloud.txt .
RUN pip install --no-cache-dir ".[cloud]" && \
    pip install --no-cache-dir -r requirements-cloud.txt

ENV PYTHONPATH=/app/src

EXPOSE 8000

COPY worker_bootstrap.py .

CMD if [ "$SERVICE_TYPE" = "worker" ]; then \
      exec python worker_bootstrap.py; \
    else \
      exec python -m uvicorn mugiwara.cloud.api:app --host 0.0.0.0 --port ${PORT:-8000}; \
    fi
