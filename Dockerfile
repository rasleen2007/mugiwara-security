FROM python:3.12-slim

WORKDIR /app

# Install full package with cloud extras (needed by worker)
COPY setup.py .
COPY src/ src/
RUN pip install --no-cache-dir ".[cloud]"

# Also install standalone cloud deps for faster API builds
COPY requirements-cloud.txt .
RUN pip install --no-cache-dir -r requirements-cloud.txt

ENV PYTHONPATH=/app/src

EXPOSE 8000

# Default: API. Set SERVICE_TYPE=worker to run the scan worker instead.
COPY worker-entrypoint.sh .
RUN chmod +x worker-entrypoint.sh
CMD if [ "$SERVICE_TYPE" = "worker" ]; then \
      exec sh worker-entrypoint.sh; \
    else \
      exec python -m uvicorn mugiwara.cloud.api:app --host 0.0.0.0 --port ${PORT:-8000}; \
    fi
