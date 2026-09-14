"""
Slice 15 tests: rate limiting.

/auth/login does real bcrypt work (settings.BCRYPT_ROUNDS=12,
deliberately slow) on completely unauthenticated input — without a
limit, that's a cheap CPU-exhaustion vector. Enforced against Redis
(core/rate_limit.py) rather than in-process memory, so it's genuinely
one shared limit rather than one limit PER uvicorn worker process.
"""

import pytest
from unittest.mock import patch
from httpx import AsyncClient
from redis.exceptions import RedisError

from app.core.config import settings
from app.models.user import User


@pytest.mark.asyncio
async def test_login_rate_limited_after_threshold(client: AsyncClient, test_user: User, monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_LOGIN_PER_MINUTE", 3)

    for _ in range(3):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "operator@testcorp.ai", "password": "wrong-password"},
        )
        # Under the limit — real auth logic still runs and correctly rejects.
        assert resp.status_code == 401

    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "operator@testcorp.ai", "password": "wrong-password"},
    )
    assert resp.status_code == 429
    assert resp.json()["detail"]["error"] == "rate_limited"


@pytest.mark.asyncio
async def test_rate_limiter_fails_open_when_redis_unreachable(client: AsyncClient, test_user: User, monkeypatch):
    """
    A rate limiter protects availability, not correctness — refusing
    ALL login traffic because Redis hiccupped would itself be a
    self-inflicted denial of service. Confirms the opposite failure
    mode from revocation.py's deliberately fail-CLOSED JTI check.
    """
    monkeypatch.setattr(settings, "RATE_LIMIT_LOGIN_PER_MINUTE", 1)

    class _BrokenRedisClient:
        async def incr(self, *args, **kwargs):
            raise RedisError("simulated outage")

    with patch("app.core.rate_limit.get_redis_client", return_value=_BrokenRedisClient()):
        for _ in range(5):
            resp = await client.post(
                "/api/v1/auth/login",
                json={"email": "operator@testcorp.ai", "password": "wrong-password"},
            )
            assert resp.status_code == 401, "must never 429 while the limiter itself can't be consulted"
