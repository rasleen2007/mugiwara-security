FROM python:3.12-slim

WORKDIR /app

COPY setup.py .
COPY src/ src/
COPY requirements-cloud.txt .
RUN pip install --no-cache-dir ".[cloud]" && \
    pip install --no-cache-dir -r requirements-cloud.txt

ENV PYTHONPATH=/app/src

COPY worker_bootstrap.py .

CMD ["python", "worker_bootstrap.py"]
