"""
Health Check Router.
Provides probes for container orchestration (`/health`) and comprehensive
system diagnostic verification (`/health/detailed`).
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import httpx

from app.db.session import get_db
from app.core.config import settings

router = APIRouter()


@router.get("")
async def health_check():
    """Liveness probe returning basic service operational status."""
    return {"status": "healthy", "service": settings.APP_NAME, "version": settings.APP_VERSION}


@router.get("/detailed")
async def detailed_health_check(db: AsyncSession = Depends(get_db)):
    """Readiness probe verifying DB, OPA, and core dependency availability."""
    db_ok = False
    db_error = None
    try:
        await db.execute(text("SELECT 1"))
        db_ok = True
    except Exception as e:
        db_error = str(e)

    opa_ok = False
    opa_error = None
    try:
        async with httpx.AsyncClient(timeout=1.5) as client:
            # Ping OPA health check endpoint
            resp = await client.get(f"{settings.OPA_URL}/health")
            if resp.status_code == 200:
                opa_ok = True
            else:
                opa_error = f"OPA returned HTTP {resp.status_code}"
    except Exception as e:
        opa_error = f"OPA connection unreachable: {e}"

    all_healthy = db_ok and opa_ok
    return {
        "status": "healthy" if all_healthy else "degraded",
        "components": {
            "database": {"status": "up" if db_ok else "down", "error": db_error},
            "opa_rebac": {"status": "up" if opa_ok else "down", "error": opa_error},
            "spiffe_spire": {"status": "configured", "trust_domain": settings.SPIFFE_TRUST_DOMAIN},
        },
    }
