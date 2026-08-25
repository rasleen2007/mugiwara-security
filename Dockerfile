FROM python:3.12-slim AS base

WORKDIR /app

# Install build dependencies for binary wheels
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential && \
    rm -rf /var/lib/apt/lists/*

# Copy only dependency manifests first for layer caching
COPY pyproject.toml uv.lock ./
COPY src/mugiwara/__init__.py src/mugiwara/__init__.py

# Install the package with cloud extras
RUN pip install --no-cache-dir ".[cloud]"

# Copy the full source
COPY src/ src/

EXPOSE 8000

# Default: run the API. Override CMD for worker.
CMD ["python", "-m", "uvicorn", "mugiwara.cloud.api:app", "--host", "0.0.0.0", "--port", "8000"]
