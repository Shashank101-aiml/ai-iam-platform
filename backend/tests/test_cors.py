"""
Slice 15 test: CORS lockdown.

allow_origins=["*"] combined with allow_credentials=True is invalid
per the Fetch/CORS spec, and every real browser silently refuses to
honor the resulting header combination — meaning the wildcard was
never actually granting credentialed cross-origin access in the first
place, it just failed client-side instead of being an honest, explicit
allowlist. This proves the app never sends that invalid combination,
and that an explicitly-configured origin still gets real CORS headers.
"""

import pytest
from httpx import AsyncClient

from app.core.config import settings


@pytest.mark.asyncio
async def test_allowed_origin_gets_credentialed_cors_headers(client: AsyncClient):
    allowed_origin = settings.CORS_ALLOWED_ORIGINS[0]
    resp = await client.get("/health", headers={"Origin": allowed_origin})
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == allowed_origin
    assert resp.headers.get("access-control-allow-credentials") == "true"
    # The one combination the spec forbids and browsers refuse to honor.
    assert resp.headers.get("access-control-allow-origin") != "*"


@pytest.mark.asyncio
async def test_unlisted_origin_gets_no_cors_headers(client: AsyncClient):
    resp = await client.get("/health", headers={"Origin": "https://evil.example"})
    assert resp.status_code == 200  # the request isn't blocked server-side...
    # ...but no header vouches for it, so a real browser's own
    # same-origin policy keeps the response from being exposed to script.
    assert "access-control-allow-origin" not in resp.headers
