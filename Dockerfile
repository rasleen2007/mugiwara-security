FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libffi-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY setup.py .
COPY src/ src/
COPY requirements-cloud.txt .
RUN pip install --no-cache-dir ".[cloud]" && \
    pip install --no-cache-dir -r requirements-cloud.txt

ENV PYTHONPATH=/app/src

EXPOSE 8000

COPY worker-entrypoint.sh .
RUN chmod +x worker-entrypoint.sh
CMD if [ "$SERVICE_TYPE" = "worker" ]; then \
      exec sh worker-entrypoint.sh; \
    else \
      exec python -m uvicorn mugiwara.cloud.api:app --host 0.0.0.0 --port ${PORT:-8000}; \
    fi
