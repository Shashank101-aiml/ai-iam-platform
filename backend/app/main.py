"""
AI-IAM Platform — FastAPI Application Entry Point.

Startup sequence:
1. Lifespan: verify DB connection, load OPA health, start background workers
2. Middleware stack (order matters — outermost runs first):
   TracePropagationMiddleware → AgentAuthMiddleware → route handlers
3. Router registration

Shutdown sequence:
1. Cancel background worker tasks
2. Close DB connection pool
"""

import asyncio
import logging
from contextlib import asynccontextmanager

from app.core.config import settings
from app.core.logging_config import configure_logging

# Called BEFORE app.db.session is imported below — that module creates
# its engines at IMPORT time, and app/db/session.py's own comment on
# `echo=False` explains why SQL logging is routed through this call's
# sql_echo flag instead of SQLAlchemy's echo= shortcut.
configure_logging(sql_echo=settings.DEBUG)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator

from app.core.jwt import verify_rs256_keypair_loadable, verify_jwt_secret_not_default
from app.core.permissions import verify_opa_reachable
from app.core.revocation import verify_redis_reachable
from app.middleware.agent_auth import AgentAuthMiddleware
from app.middleware.trace_propagation import TracePropagationMiddleware
from app.db.session import engine

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle management."""

    # ── Startup ──────────────────────────────────────────────────────────────
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")

    # Refuse to boot on the well-known default JWT_SECRET_KEY — see
    # core/jwt.py's verify_jwt_secret_not_default docstring.
    verify_jwt_secret_not_default(debug=settings.DEBUG)

    # Verify DB connectivity
    try:
        async with engine.connect() as conn:
            from sqlalchemy import text
            await conn.execute(text("SELECT 1"))
        logger.info("Database connection verified")
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        raise

    # Verify the RS256 keypair agent tokens are signed/verified with is
    # present and actually matched — not lazily, on the first agent's
    # first request. JWT_SECRET_KEY (operator HS256) has no default in
    # Settings, so it already blocks startup on its own if missing.
    try:
        verify_rs256_keypair_loadable()
        logger.info("RS256 agent token keypair verified")
    except Exception as e:
        logger.error(f"RS256 keypair invalid or unreadable: {e}")
        raise

    # Verify OPA is reachable — see verify_opa_reachable's docstring for
    # why this refuses to boot rather than starting degraded.
    try:
        await verify_opa_reachable()
        logger.info(
            "OPA policy engine reachable" if settings.OPA_REQUIRED
            else "OPA_REQUIRED=false — skipped OPA reachability check"
        )
    except Exception as e:
        logger.error(f"OPA reachability check failed: {e}")
        raise

    # Verify the revocation index is reachable — see
    # verify_redis_reachable's docstring for why this refuses to boot
    # rather than starting with revocation silently unenforceable.
    try:
        await verify_redis_reachable()
        logger.info(
            "Revocation index (Redis) reachable" if settings.REDIS_REQUIRED
            else "REDIS_REQUIRED=false — skipped Redis reachability check"
        )
    except Exception as e:
        logger.error(f"Redis reachability check failed: {e}")
        raise

    # Start background workers
    worker_task = asyncio.create_task(_start_workers())
    audit_verifier_task = asyncio.create_task(_start_audit_verifier())
    logger.info("Background workers started")

    yield  # Application runs here

    # ── Shutdown ─────────────────────────────────────────────────────────────
    for task in (worker_task, audit_verifier_task):
        task.cancel()
    for task in (worker_task, audit_verifier_task):
        try:
            await task
        except asyncio.CancelledError:
            pass

    await engine.dispose()
    logger.info("Shutdown complete")


async def _start_workers():
    """Launch background maintenance workers."""
    from app.worker.credential_rotator import run_worker_loop
    await run_worker_loop(interval_seconds=300)


async def _start_audit_verifier():
    """
    Launch the periodic audit hash-chain verifier as its own task, on its
    own (much longer) interval — see AUDIT_VERIFY_INTERVAL_SECONDS.
    """
    from app.worker.audit_verifier import run_audit_verifier_loop
    await run_audit_verifier_loop(interval_seconds=settings.AUDIT_VERIFY_INTERVAL_SECONDS)


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "Agent Identity & Access Management Platform. "
            "Auth0 for AI Agents — register, credential, govern, audit."
        ),
        docs_url="/docs" if settings.DEBUG else None,
        redoc_url="/redoc" if settings.DEBUG else None,
        lifespan=lifespan,
    )

    # ── Middleware (outermost first) ──────────────────────────────────────────
    # NEVER allow_origins=["*"] here — combined with allow_credentials=
    # True (needed for the dashboard's session cookie/Authorization
    # header) that's invalid per the Fetch/CORS spec, and every real
    # browser refuses to honor it, so the wildcard was never actually
    # granting cross-origin access in the first place — it just failed
    # silently client-side instead of being an honest, explicit list.
    # settings.CORS_ALLOWED_ORIGINS defaults to the local frontend dev
    # origin; set it to the real deployed dashboard origin(s) in prod.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    # Trace first — injects trace_id before auth runs
    app.add_middleware(TracePropagationMiddleware)
    # Auth second — uses trace_id set above
    app.add_middleware(AgentAuthMiddleware)

    # ── Routers ───────────────────────────────────────────────────────────────
    from app.api import (
        health, auth, organizations, agents,
        api_keys, audit_logs, mcp_proxy, token, roles, users,
        oauth, well_known, overview,
    )

    prefix = "/api/v1"
    # health.router defines its liveness route as `@router.get("")` — an
    # empty prefix here combined with that empty path is invalid and
    # FastAPI refuses to construct the app at all ("Prefix and path cannot
    # be both empty"). "/health" matches what AgentAuthMiddleware's
    # EXCLUDED_PATHS already assumes, and — since Slice 14 — what the
    # Dockerfile's own HEALTHCHECK actually probes too (it used to probe
    # /api/v1/health, a path that never existed).
    app.include_router(health.router, prefix="/health", tags=["health"])
    app.include_router(auth.router, prefix=f"{prefix}/auth", tags=["auth"])
    app.include_router(organizations.router, prefix=f"{prefix}/organizations", tags=["organizations"])
    app.include_router(agents.router, prefix=f"{prefix}/agents", tags=["agents"])
    app.include_router(api_keys.router, prefix=f"{prefix}/keys", tags=["credentials"])
    app.include_router(audit_logs.router, prefix=f"{prefix}/audit", tags=["audit"])
    app.include_router(mcp_proxy.router, prefix=f"{prefix}/mcp", tags=["mcp"])
    app.include_router(token.router, prefix=f"{prefix}/token", tags=["token"])
    app.include_router(roles.router, prefix=f"{prefix}/roles", tags=["roles"])
    app.include_router(users.router, prefix=f"{prefix}/users", tags=["users"])
    app.include_router(oauth.router, prefix=f"{prefix}/oauth", tags=["oauth"])
    app.include_router(overview.router, prefix=f"{prefix}/overview", tags=["overview"])
    # No prefix — RFC 8414/9728 require these at a fixed root-level path.
    app.include_router(well_known.router, tags=["discovery"])

    # /metrics: generic HTTP request-count/latency histograms (by route,
    # method, status code) from the instrumentator itself, PLUS the
    # domain counters/histograms in core/metrics.py, which get pulled
    # into the same default Prometheus registry the instrumentator
    # exposes just by being instantiated anywhere in the process — no
    # separate wiring needed for those. Unauthenticated, matching the
    # standard Prometheus scrape convention (a scraper on the internal
    # network, not a browser); AgentAuthMiddleware doesn't gate this
    # path either way since _requires_agent_auth only matches specific
    # agent-facing prefixes /metrics isn't one of.
    Instrumentator().instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)

    return app


app = create_app()
