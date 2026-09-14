"""
Slice 14 tests: liveness/readiness split.

/health is what a container orchestrator's liveness probe hits — it
must NEVER depend on Postgres/OPA, or a brief blip in either takes down
a process that was otherwise perfectly fine to keep serving traffic,
and (under a real orchestrator whose liveness probe triggers restarts,
unlike bare `docker`) can cascade into a restart storm.
/health/detailed is the separate READINESS probe that's supposed to
reflect exactly that dependency state. These two routes doing
different jobs is the whole point of the split — this proves it holds,
not just that both return 200 when everything happens to be healthy.
"""

import pytest
from httpx import AsyncClient

from app.core.config import settings


@pytest.mark.asyncio
async def test_liveness_ignores_a_dead_opa(client: AsyncClient, monkeypatch):
    monkeypatch.setattr(settings, "OPA_URL", "http://127.0.0.1:1")

    liveness = await client.get("/health")
    assert liveness.status_code == 200
    assert liveness.json()["status"] == "healthy"

    readiness = await client.get("/health/detailed")
    assert readiness.status_code == 200
    body = readiness.json()
    assert body["status"] == "degraded"
    assert body["components"]["opa_rebac"]["status"] == "down"
    # DB was never touched by this test — only OPA should read as down,
    # proving the two component checks are independent of each other.
    assert body["components"]["database"]["status"] == "up"


@pytest.mark.asyncio
async def test_readiness_reports_healthy_when_everything_is_up(client: AsyncClient):
    resp = await client.get("/health/detailed")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "healthy"
    assert body["components"]["database"]["status"] == "up"
    assert body["components"]["opa_rebac"]["status"] == "up"
