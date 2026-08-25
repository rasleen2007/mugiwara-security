FROM python:3.12-slim

WORKDIR /app

COPY setup.py .
COPY src/ src/
RUN pip install --no-cache-dir ".[cloud]"

ENV PYTHONPATH=/app/src

CMD ["python", "-m", "mugiwara.cloud.worker"]
