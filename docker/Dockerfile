# Multi-stage production Dockerfile for AI-IAM Platform Backend
#
# Both stages pin python:3.11-slim by digest, not just the tag (Slice
# 15) — a tag can be silently repointed at a different underlying image
# upstream at any time; a digest is the actual content, immune to that.
# Re-resolve deliberately (`docker pull python:3.11-slim && docker
# inspect ... RepoDigests`) to pick up a real security patch — don't
# let the base image drift silently, but don't let it drift by accident
# either.
FROM python:3.11-slim@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534 AS builder

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


FROM python:3.11-slim@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534 AS runtime

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

# main.py mounts health.router at the root-level "/health" (not under
# /api/v1 — see its comment there for why: health.router's liveness
# route is defined as @router.get("") and FastAPI refuses an empty
# prefix + empty path combo, plus AgentAuthMiddleware's EXCLUDED_PATHS
# already assumes "/health" unprefixed). This used to probe
# /api/v1/health, a path that has never existed — every prior
# container was reporting unhealthy from the moment it passed
# --start-period, on a path that 404s (Slice 14).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
