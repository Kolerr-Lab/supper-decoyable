# syntax=docker/dockerfile:1

# ---- Build stage ----
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VENV_PATH=/opt/venv

WORKDIR /src

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends build-essential gcc ca-certificates && rm -rf /var/lib/apt/lists/*

# Create virtualenv and upgrade pip
RUN python -m venv ${VENV_PATH} \
    && ${VENV_PATH}/bin/pip install --upgrade pip setuptools wheel

# Copy dependency manifests first
COPY requirements.txt ./
COPY pyproject.toml ./

# Install dependencies
RUN ${VENV_PATH}/bin/pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# ---- Runtime stage ----
FROM python:3.11-slim AS runtime

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_HOME=/app \
    PORT=8000

WORKDIR ${APP_HOME}

# Copy virtualenv and app from builder
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /src ${APP_HOME}

# Create non-root user
RUN addgroup --system app && adduser --system --ingroup app app
RUN apt-get update && apt-get install -y --no-install-recommends curl iptables && rm -rf /var/lib/apt/lists/*
RUN chown -R app:app ${APP_HOME}
USER app

# Expose main application port
EXPOSE ${PORT}

# Expose decoy ports for honeypot services (configured via DECOY_PORTS env var)
# These ports will be exposed at runtime based on DECOY_PORTS environment variable

# Healthcheck endpoint
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Start with Uvicorn for FastAPI
CMD ["uvicorn", "decoyable.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
