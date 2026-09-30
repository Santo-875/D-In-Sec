# ================================================================
# D-In-Sec Module 3 — Cloud-Ready API Sidecar Container
# Python 3.13-slim base, non-root user, multi-stage minimal build
# ================================================================

FROM python:3.13-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    M3_STORAGE_BACKEND=local \
    M3_SIGNER_BACKEND=local \
    M3_PORT=5001

WORKDIR /app

# System dependencies for cryptography and sqlite
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create unprivileged application user
RUN useradd -m -u 10001 -s /bin/bash appuser

# Copy codebase
COPY . .

# Set permissions for local SQLite storage and logs
RUN mkdir -p /app/local_storage /app/data && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 5001

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:5001/healthz || exit 1

ENTRYPOINT ["gunicorn", "-w", "4", "-b", "0.0.0.0:5001", "m3.api:create_m3_app()", "--timeout", "120"]
