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

COPY worker-entrypoint.sh .
RUN chmod +x worker-entrypoint.sh

CMD ["sh", "worker-entrypoint.sh"]
