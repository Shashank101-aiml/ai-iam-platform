"""
Credential Rotator Worker.

Runs on a schedule (cron or APScheduler) to proactively rotate
API keys that are within the last 20% of their TTL.

Why proactive rotation?
- Reactive rotation (after expiry) = production outage
- Proactive rotation = zero-downtime, agents get the new key
  during the grace window before the old one expires

In production: run as a separate process or Celery beat task.
For this project: wired up via lifespan events in main.py.
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta

from app.core.metrics import CREDENTIAL_ROTATIONS_TOTAL
from app.core.worker_lock import try_acquire
from app.db.session import AsyncSessionLocal
from app.repositories.api_key_repo import api_key_repo
from app.services.api_key_service import api_key_service

logger = logging.getLogger(__name__)

_ROTATE_LOCK = "aiiam:credential_rotator:rotate_expiring_keys"
_REAPER_LOCK = "aiiam:credential_rotator:decommission_ephemeral"


async def rotate_expiring_keys() -> dict:
    """
    Find and rotate all keys within the rotation window.
    Returns a summary of what was rotated.

    Guarded by a Postgres advisory lock (Slice 15) — a real deployment
    runs multiple web worker processes (this project's own Dockerfile
    CMD: `--workers 4`), each running its own copy of this loop with no
    other coordination. Without this, every process would rotate the
    SAME keys on the SAME schedule, racing each other. Only the process
    whose transaction wins the lock for this cycle does anything; every
    other process's call returns immediately with rotated_count=0 and
    skipped=True, never having touched a single key.
    """
    rotated = []
    errors = []

    async with AsyncSessionLocal() as db:
        try:
            if not await try_acquire(db, _ROTATE_LOCK):
                logger.info("Credential rotator: another worker process holds this cycle's lock — skipping")
                await db.commit()  # releases nothing (we hold no lock) — just closes the transaction cleanly
                return {
                    "rotated_count": 0,
                    "error_count": 0,
                    "rotated": [],
                    "errors": [],
                    "skipped": True,
                    "ran_at": datetime.now(timezone.utc).isoformat(),
                }

            keys = await api_key_repo.get_keys_needing_rotation(db)
            logger.info(f"Credential rotator: found {len(keys)} keys needing rotation")

            for key in keys:
                try:
                    result = await api_key_service.rotate_key(
                        db,
                        key_id=key.key_id,
                        org_id=key.org_id,
                        actor_id="system:credential_rotator",
                        grace_period_hours=2,
                    )
                    rotated.append({
                        "old_key_id": key.key_id,
                        "new_key_id": result["key_id"],
                        "agent_id": key.agent_id,
                    })
                    CREDENTIAL_ROTATIONS_TOTAL.inc()
                    logger.info(
                        f"Rotated key {key.key_id} → {result['key_id']} "
                        f"for agent {key.agent_id}"
                    )
                except Exception as e:
                    errors.append({"key_id": key.key_id, "error": str(e)})
                    logger.error(f"Failed to rotate key {key.key_id}: {e}")

            await db.commit()

        except Exception as e:
            await db.rollback()
            logger.error(f"Credential rotator transaction failed: {e}")
            raise

    return {
        "rotated_count": len(rotated),
        "error_count": len(errors),
        "rotated": rotated,
        "errors": errors,
        "skipped": False,
        "ran_at": datetime.now(timezone.utc).isoformat(),
    }


async def decommission_expired_ephemeral_agents() -> dict:
    """
    Find ephemeral agents past their decommission_at time and decommission them.
    Prevents zombie agents accumulating with stale credentials.
    """
    from app.repositories.agent_repo import agent_repo
    from app.services.agent_service import agent_service

    decommissioned = []
    errors = []

    async with AsyncSessionLocal() as db:
        try:
            if not await try_acquire(db, _REAPER_LOCK):
                logger.info("Ephemeral reaper: another worker process holds this cycle's lock — skipping")
                await db.commit()
                return {
                    "decommissioned_count": 0,
                    "error_count": 0,
                    "skipped": True,
                    "ran_at": datetime.now(timezone.utc).isoformat(),
                }

            now = datetime.now(timezone.utc)
            expired = await agent_repo.get_expiring_ephemeral(db, before=now)
            logger.info(f"Ephemeral reaper: found {len(expired)} agents to decommission")

            for agent in expired:
                try:
                    await agent_service.decommission(
                        db,
                        agent_id=agent.id,
                        org_id=agent.org_id,
                        reason="ephemeral_ttl_expired",
                        actor_id="system:ephemeral_reaper",
                    )
                    decommissioned.append(agent.id)
                    logger.info(f"Decommissioned ephemeral agent {agent.id}")
                except Exception as e:
                    errors.append({"agent_id": agent.id, "error": str(e)})
                    logger.error(f"Failed to decommission agent {agent.id}: {e}")

            await db.commit()

        except Exception as e:
            await db.rollback()
            raise

    return {
        "decommissioned_count": len(decommissioned),
        "error_count": len(errors),
        "skipped": False,
        "ran_at": datetime.now(timezone.utc).isoformat(),
    }


async def run_worker_loop(interval_seconds: int = 300):
    """
    Run both workers in a loop. Called from main.py lifespan.
    Default: every 5 minutes.
    """
    while True:
        try:
            rotation_result = await rotate_expiring_keys()
            reaper_result = await decommission_expired_ephemeral_agents()
            logger.info(
                f"Worker cycle complete. "
                f"Rotated: {rotation_result['rotated_count']}, "
                f"Decommissioned: {reaper_result['decommissioned_count']}"
            )
        except Exception as e:
            logger.error(f"Worker loop error: {e}")

        await asyncio.sleep(interval_seconds)
