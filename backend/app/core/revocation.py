"""
JTI revocation index — closes the gap short token TTLs don't: every
revoke path in this platform (API key revoked, delegation grant
revoked, agent suspended/decommissioned) used to only flip a database
flag that nothing in the request path ever consulted. A revoked
agent's or delegation's already-issued tokens kept working until they
naturally expired.

Design:
- `revoked_jti:{jti}` — a plain key, set on revocation, TTL'd to exactly
  the token's own remaining lifetime. is_revoked() is one EXISTS call
  on the hot path (every agent request), and Redis itself garbage-
  collects the entry the moment it would have expired anyway — nothing
  ever needs to sweep this index.
- `agent:{agent_id}:jtis` / `key:{key_id}:jtis` — sorted sets (score =
  the token's own exp, a unix timestamp) populated at MINT time by
  every call site that issues an agent-bearing token (token exchange,
  delegation). These are the reverse indexes cascade revocation reads:
  "every token ever issued to this agent" or "...from this API key" —
  without them, revoking an agent would have no way to find which
  jtis to blacklist, since JWTs are otherwise stateless.

Fail-closed on Redis being unreachable — the same choice this project
already made for OPA (see core/permissions.py's verify_opa_reachable)
and for the same reason: an unreachable revocation index would
silently let every already-revoked token through while looking "up"
from the outside. is_revoked() raises RevocationCheckUnavailable rather
than returning True/False so the caller can tell "known revoked" apart
from "couldn't check" — both end in a denial, but only one is honest
about why in logs/monitoring.
"""

import time
import logging
from typing import Optional

import redis.asyncio as redis
from redis.exceptions import RedisError

from app.core.config import settings

logger = logging.getLogger(__name__)

_redis_client: Optional["redis.Redis"] = None


def get_redis_client() -> "redis.Redis":
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis_client


async def reset_redis_client() -> None:
    """
    Drop the cached client so the next get_redis_client() call opens a
    fresh connection pool. redis.asyncio's pool binds its connections to
    the event loop that was running when they were opened; a module-
    level singleton reused across pytest-asyncio's per-function event
    loops (this project's default: asyncio_default_fixture_loop_scope =
    function) crashes with "attached to a different loop" the moment a
    later test tries to reuse a connection opened under an earlier
    test's now-closed loop. Not needed in the real app, which runs one
    event loop for its whole process lifetime — only test isolation
    needs this.
    """
    global _redis_client
    if _redis_client is not None:
        try:
            await _redis_client.aclose()
        except Exception:
            pass
        _redis_client = None


class RevocationCheckUnavailable(Exception):
    """Raised when the revocation index can't be consulted at all (Redis down/unreachable)."""


async def verify_redis_reachable() -> None:
    """
    Fail fast at startup if Redis is required but unreachable — called
    from main.py's lifespan, gated by settings.REDIS_REQUIRED (default
    True). Mirrors verify_opa_reachable's rationale exactly: a
    revocation index that's silently unreachable would look "up" from
    the outside while every revoked token keeps working forever.
    """
    if not settings.REDIS_REQUIRED:
        return
    try:
        await get_redis_client().ping()
    except RedisError as e:
        raise RuntimeError(
            f"Redis is required (REDIS_REQUIRED=true) but unreachable at "
            f"'{settings.REDIS_URL}': {e}. Set REDIS_REQUIRED=false only "
            f"for narrow local work that doesn't exercise revocation."
        ) from e


async def is_revoked(jti: str) -> bool:
    """
    Check whether a jti has been revoked. Raises RevocationCheckUnavailable
    if Redis can't be reached — the caller (AgentAuthMiddleware) treats
    that as a denial too, just with a distinguishable reason.
    """
    try:
        return await get_redis_client().exists(f"revoked_jti:{jti}") == 1
    except RedisError as e:
        raise RevocationCheckUnavailable(str(e)) from e


async def revoke_jti(jti: str, ttl_seconds: int) -> None:
    """
    Blacklist a single jti for (at most) its own remaining lifetime —
    there's never a reason to remember a revocation longer than the
    token itself would have been valid for.
    """
    ttl = max(int(ttl_seconds), 1)
    await get_redis_client().set(f"revoked_jti:{jti}", "1", ex=ttl)


async def track_issued_jti(index_key: str, jti: str, exp_unix_ts: int) -> None:
    """
    Record that `jti` (expiring at `exp_unix_ts`) was issued under
    `index_key` — e.g. f"agent:{agent_id}:jtis" or f"key:{key_id}:jtis"
    — so a later cascade revoke (agent suspended, key revoked) can find
    every token it needs to blacklist. A sorted set scored by exp: an
    unrevoked entry is harmless dead weight once its token naturally
    expires (score < now), so revoke_all_in_index() only bothers
    blacklisting members that haven't expired yet, and this same
    opportunistic pruning keeps the index from growing without bound.
    """
    client = get_redis_client()
    await client.zadd(index_key, {jti: exp_unix_ts})
    # Opportunistic cleanup — bounds the index's size without a separate
    # sweep job; safe to run on every write since it only ever removes
    # entries whose tokens are already dead regardless.
    await client.zremrangebyscore(index_key, "-inf", int(time.time()))


async def revoke_all_in_index(index_key: str) -> int:
    """
    Blacklist every still-live jti tracked under `index_key`, then clear
    the index. Returns how many jtis were actually revoked (already-
    expired members are skipped — nothing to revoke, they're dead).
    """
    client = get_redis_client()
    now = int(time.time())
    members = await client.zrangebyscore(index_key, now, "+inf", withscores=True)
    count = 0
    for jti, exp in members:
        await revoke_jti(jti, int(exp - now))
        count += 1
    await client.delete(index_key)
    return count
