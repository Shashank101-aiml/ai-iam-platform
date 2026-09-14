"""
Audit Chain Verifier Worker.

Runs on a schedule (wired into the same worker loop as the credential
rotator — see main.py's lifespan) to replay every org's tamper-evident
hash chain and raise a loud alert the moment one is found broken,
instead of the only way to discover tampering being an operator
happening to call GET /api/v1/audit/verify.

Uses audit_repo.verify_chain's streaming implementation (yield_per,
never materializes a whole org's history at once), so this scales to an
org with millions of entries in fixed memory — the same property the
on-demand endpoint gets for free from the same code path.
"""

import asyncio
import logging

from app.core.worker_lock import try_acquire
from app.db.session import AsyncSessionLocal
from app.repositories.organization_repo import org_repo
from app.repositories.audit_repo import audit_repo

logger = logging.getLogger(__name__)

_VERIFIER_LOCK = "aiiam:audit_verifier:verify_all_audit_chains"


async def verify_all_audit_chains() -> dict:
    """
    Replay the audit chain for every organization and report any that
    fail cryptographic verification.

    Returns a summary; logs a CRITICAL alert per broken chain so it
    surfaces in whatever log aggregation is watching this process,
    without waiting for a human to poll the verify endpoint.

    Guarded by a Postgres advisory lock (Slice 15), held for this
    entire function's duration via a dedicated session that never
    commits until the very end — every actual per-org verification
    below still runs through its own separate AsyncSessionLocal(), as
    it always did; this outer session's only job is holding the lock
    across all of them. Without this, a multi-worker-process deployment
    (this project's own Dockerfile CMD: `--workers 4`) would have every
    process replaying and re-hashing every org's ENTIRE chain on the
    same schedule — wasted, redundant work against a real database, not
    just a log-noise nuisance.
    """
    async with AsyncSessionLocal() as lock_session:
        if not await try_acquire(lock_session, _VERIFIER_LOCK):
            logger.info("Audit chain verifier: another worker process holds this cycle's lock — skipping")
            await lock_session.commit()
            return {
                "verified_count": 0, "broken_count": 0, "error_count": 0,
                "verified": [], "broken": [], "errors": [], "skipped": True,
            }

        result = await _verify_all_audit_chains_locked()
        await lock_session.commit()  # releases the advisory lock
        return result


async def _verify_all_audit_chains_locked() -> dict:
    """The actual verification work — only ever reached while _VERIFIER_LOCK is held."""
    verified = []
    broken = []
    errors = []

    async with AsyncSessionLocal() as db:
        orgs = await org_repo.list_all(db, limit=1000)

    for org in orgs:
        try:
            async with AsyncSessionLocal() as db:
                is_valid, broken_at, total_checked = await audit_repo.verify_chain(db, org.id)
            if is_valid:
                verified.append({"org_id": org.id, "entries_checked": total_checked})
            else:
                broken.append({
                    "org_id": org.id,
                    "broken_at_sequence": broken_at,
                    "entries_checked": total_checked,
                })
                logger.critical(
                    f"TAMPER DETECTED: org {org.id}'s audit hash chain is broken at "
                    f"sequence {broken_at}. Escalate to security team immediately."
                )
        except Exception as e:
            errors.append({"org_id": org.id, "error": str(e)})
            logger.error(f"Audit chain verification failed for org {org.id}: {e}")

    if broken:
        logger.critical(
            f"Audit chain verifier: {len(broken)} of {len(orgs)} org(s) failed "
            f"tamper verification."
        )
    else:
        logger.info(
            f"Audit chain verifier: {len(verified)} org(s) verified clean, "
            f"{len(errors)} error(s)."
        )

    return {
        "verified_count": len(verified),
        "broken_count": len(broken),
        "error_count": len(errors),
        "verified": verified,
        "broken": broken,
        "errors": errors,
        "skipped": False,
    }


async def run_audit_verifier_loop(interval_seconds: int) -> None:
    """
    Run verify_all_audit_chains on a loop. Called from main.py's lifespan
    as its own task, on its own (much longer) interval than the
    credential-rotation/ephemeral-reaper loop — see
    AUDIT_VERIFY_INTERVAL_SECONDS's docstring for why the two shouldn't
    share a cadence.
    """
    while True:
        try:
            await verify_all_audit_chains()
        except Exception as e:
            logger.error(f"Audit verifier loop error: {e}")

        await asyncio.sleep(interval_seconds)
