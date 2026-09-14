"""
Postgres advisory-lock helper for singleton background work (Slice 15).

This app's background workers (credential rotator, ephemeral reaper,
audit chain verifier — see app/worker/) are started from main.py's
lifespan, which runs once PER PROCESS. A real deployment runs multiple
web worker processes behind one listening port (this project's own
Dockerfile CMD uses `--workers 4`) — with no coordination, every one of
those processes would run every worker on the same schedule, all
racing to rotate the same keys, decommission the same agents, and
verify the same audit chains concurrently. `pg_try_advisory_xact_lock`
is the same mechanism `audit_repo._get_chain_tip` already uses to
serialize concurrent audit appends (Slice 8) — reused here for a
different purpose: whichever process's transaction acquires the lock
first for a given cycle does the work; every other process's attempt
returns False immediately (never blocks) and that process simply skips
this cycle. The lock is transaction-scoped, so it releases automatically
on commit or rollback — no separate unlock call, and no risk of leaking
a held lock into a pooled connection that outlives the caller's logical
unit of work.
"""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def try_acquire(db: AsyncSession, lock_name: str) -> bool:
    """
    Attempt to acquire a named advisory lock scoped to `db`'s CURRENT
    transaction. Returns True if acquired (caller should proceed and
    later commit/rollback `db` as normal — that's what releases it),
    False if another session already holds it (caller should skip this
    cycle without touching `db` further).
    """
    result = await db.execute(
        text("SELECT pg_try_advisory_xact_lock(hashtext(:lock_name))"),
        {"lock_name": lock_name},
    )
    return bool(result.scalar())
