"""
Redis-backed fixed-window rate limiter (Slice 15).

Protects /auth/login and /token/exchange, both of which do bcrypt work
(deliberately slow — see settings.BCRYPT_ROUNDS) on completely
unauthenticated input. An in-process counter would only bound each of
the 4 uvicorn worker processes independently — a client could get up
to 4x the intended limit purely by chance of which worker handled each
request — so this counts against Redis, already a hard dependency
every worker shares (see core/revocation.py).

Deliberately FAILS OPEN on a Redis outage — the opposite trust posture
from revocation.py's fail-closed JTI check. Revocation protects
correctness (an already-revoked token must never work); this protects
availability. Refusing all login/token-exchange traffic because Redis
hiccupped would itself be a self-inflicted denial of service, almost
certainly worse than the abuse a rate limiter defends against for the
handful of seconds a real outage typically lasts.
"""

import time

from fastapi import HTTPException, Request, status
from redis.exceptions import RedisError

from app.core.config import settings
from app.core.revocation import get_redis_client


async def enforce_rate_limit(request: Request, *, bucket: str, limit: int, window_seconds: int = 60) -> None:
    """
    Fixed-window counter keyed by (bucket, client IP, window index).
    Raises 429 once `limit` requests land in the same window for the
    same bucket+IP; silently no-ops (fails open) if Redis can't be
    reached at all.
    """
    client_ip = request.client.host if request.client else "unknown"
    window = int(time.time() // window_seconds)
    key = f"ratelimit:{bucket}:{client_ip}:{window}"

    try:
        client = get_redis_client()
        count = await client.incr(key)
        if count == 1:
            # Only the request that just created this window's counter
            # sets its expiry — every subsequent INCR in the same window
            # must not accidentally extend it.
            await client.expire(key, window_seconds)
    except RedisError:
        return

    if count > limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "rate_limited",
                "detail": f"Too many requests; try again in under {window_seconds} seconds.",
            },
        )


async def rate_limit_login(request: Request) -> None:
    await enforce_rate_limit(
        request, bucket="auth_login", limit=settings.RATE_LIMIT_LOGIN_PER_MINUTE
    )


async def rate_limit_token_exchange(request: Request) -> None:
    await enforce_rate_limit(
        request, bucket="token_exchange", limit=settings.RATE_LIMIT_TOKEN_EXCHANGE_PER_MINUTE
    )
