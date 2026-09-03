# Multi-stage production Dockerfile for AI-IAM Platform Backend
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies into a virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt


FROM python:3.11-slim as runtime

WORKDIR /app

# Install runtime postgres client libraries and openssl for key management
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    openssl \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
# scripts/seed_db.py is invoked as `python ../scripts/seed_db.py` (see
# docker-compose.yml) — direct script invocation puts the script's own
# directory on sys.path, not the working directory, so without this the
# `app` package under /app/backend would not be importable from it.
ENV PYTHONPATH=/app/backend

# Create non-root user for security
RUN groupadd -g 1001 aiiam && \
    useradd -r -u 1001 -g aiiam aiiam

# Copy application source and scripts
COPY --chown=aiiam:aiiam backend /app/backend
COPY --chown=aiiam:aiiam scripts /app/scripts

WORKDIR /app/backend

USER aiiam

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
