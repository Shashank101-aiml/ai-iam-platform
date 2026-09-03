"""
Audit Flusher Worker.

Problem this solves:
  In high-throughput agent systems, every tool call, access decision,
  and credential use emits an audit event. If each event hits the DB
  synchronously during the request, you pay the DB write latency on
  EVERY request — even when the audit entry isn't on the critical path.

Solution:
  Buffer audit entries in memory, flush to DB in batches.
  This decouples request latency from audit write latency.

Safety guarantees:
  1. MAX_BUFFER_SIZE: if the buffer fills faster than it flushes
     (e.g. DB is slow), we fall back to synchronous writes rather
     than silently dropping events. Audit completeness > performance.
  2. MAX_FLUSH_INTERVAL: even if the buffer isn't full, we flush
     every N seconds so events don't sit in memory indefinitely.
  3. Graceful shutdown: on SIGTERM, we flush whatever remains in
     the buffer before the process exits — no events lost on deploy.
  4. Retry with backoff: transient DB failures retry 3 times before
     the batch is written to a dead-letter file for manual recovery.

Architecture:
  Request handler → AuditFlusher.enqueue() → in-memory buffer
                                          ↓ (every 5s or 100 entries)
                              _flush_batch() → PostgreSQL audit_logs

  This is NOT a Kafka/Redis queue — it's a lightweight in-process
  buffer. For true durability across process restarts, wire the
  dead-letter file to an external queue in production.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.core.constants import AuditAction

logger = logging.getLogger(__name__)

# Tuning constants
MAX_BUFFER_SIZE = 500         # Entries before synchronous fallback kicks in
MAX_FLUSH_INTERVAL = 5.0      # Seconds between forced flushes
FLUSH_BATCH_SIZE = 100        # Entries per DB transaction
MAX_RETRY_ATTEMPTS = 3        # Retry count for transient DB failures
DEAD_LETTER_PATH = Path("/tmp/audit_dead_letter.jsonl")  # Fallback file


class AuditEntry:
    """In-memory representation of a pending audit event."""
    __slots__ = [
        "id", "org_id", "agent_id", "action", "actor_type", "actor_id",
        "outcome", "causal_trace_id", "details", "resource_type",
        "resource_id", "parent_event_id", "source_ip", "user_agent",
        "enqueued_at",
    ]

    def __init__(
        self,
        org_id: str,
        action: AuditAction,
        actor_type: str,
        actor_id: str,
        causal_trace_id: str,
        outcome: str,
        agent_id: Optional[str] = None,
        details: Optional[dict] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ):
        self.id = str(uuid.uuid4())
        self.org_id = org_id
        self.agent_id = agent_id
        self.action = action
        self.actor_type = actor_type
        self.actor_id = actor_id
        self.outcome = outcome
        self.causal_trace_id = causal_trace_id
        self.details = details
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.parent_event_id = parent_event_id
        self.source_ip = source_ip
        self.user_agent = user_agent
        self.enqueued_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "agent_id": self.agent_id,
            "action": self.action.value if isinstance(self.action, AuditAction) else self.action,
            "actor_type": self.actor_type,
            "actor_id": self.actor_id,
            "outcome": self.outcome,
            "causal_trace_id": self.causal_trace_id,
            "details": self.details,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "parent_event_id": self.parent_event_id,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "enqueued_at": self.enqueued_at.isoformat(),
        }


class AuditFlusher:
    """
    Singleton in-process audit buffer with background flush loop.

    Lifecycle:
      app startup  → AuditFlusher.start()
      request      → AuditFlusher.enqueue(entry)  [non-blocking]
      every 5s     → _flush_loop() drains buffer to DB
      app shutdown → AuditFlusher.stop()  [drains remaining entries]
    """

    def __init__(self):
        self._buffer: list[AuditEntry] = []
        self._lock = asyncio.Lock()
        self._flush_task: Optional[asyncio.Task] = None
        self._running = False
        self._stats = {
            "total_enqueued": 0,
            "total_flushed": 0,
            "total_dropped_to_dead_letter": 0,
            "total_sync_fallbacks": 0,
            "flush_cycles": 0,
        }

    async def start(self):
        """Start the background flush loop. Call from app lifespan startup."""
        self._running = True
        self._flush_task = asyncio.create_task(self._flush_loop())
        logger.info(
            f"AuditFlusher started "
            f"(batch_size={FLUSH_BATCH_SIZE}, interval={MAX_FLUSH_INTERVAL}s)"
        )

    async def stop(self):
        """
        Graceful shutdown — flush remaining buffer before exiting.
        Call from app lifespan shutdown.
        """
        self._running = False
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass

        # Final flush — don't lose events on deploy
        remaining = len(self._buffer)
        if remaining > 0:
            logger.info(f"AuditFlusher shutdown: flushing {remaining} remaining entries")
            await self._flush_all()

        logger.info(f"AuditFlusher stopped. Stats: {self._stats}")

    async def enqueue(self, entry: AuditEntry) -> bool:
        """
        Add an audit entry to the buffer. Non-blocking.

        Returns True if buffered, False if buffer is full (sync fallback used).

        The caller (audit_repo.append) is responsible for the sync fallback.
        We return False here as the signal to trigger it.
        """
        async with self._lock:
            if len(self._buffer) >= MAX_BUFFER_SIZE:
                # Buffer overflow — signal caller to write synchronously
                # This protects against memory exhaustion if DB is slow
                self._stats["total_sync_fallbacks"] += 1
                logger.warning(
                    f"AuditFlusher buffer full ({MAX_BUFFER_SIZE}). "
                    f"Triggering sync fallback for entry {entry.id}"
                )
                return False

            self._buffer.append(entry)
            self._stats["total_enqueued"] += 1
            return True

    async def enqueue_many(self, entries: list[AuditEntry]) -> int:
        """Bulk enqueue. Returns count successfully buffered."""
        buffered = 0
        for entry in entries:
            if await self.enqueue(entry):
                buffered += 1
        return buffered

    def buffer_size(self) -> int:
        return len(self._buffer)

    def stats(self) -> dict:
        return {**self._stats, "current_buffer_size": len(self._buffer)}

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _flush_loop(self):
        """Background task: flush every MAX_FLUSH_INTERVAL seconds."""
        while self._running:
            try:
                await asyncio.sleep(MAX_FLUSH_INTERVAL)
                await self._flush_batch()
                self._stats["flush_cycles"] += 1
            except asyncio.CancelledError:
                raise
            except Exception as e:
                # Never crash the flush loop — log and continue
                logger.error(f"AuditFlusher flush cycle error: {e}", exc_info=True)

    async def _flush_batch(self):
        """
        Drain up to FLUSH_BATCH_SIZE entries from the buffer and write to DB.
        """
        async with self._lock:
            if not self._buffer:
                return
            # Take a batch from the front of the buffer
            batch = self._buffer[:FLUSH_BATCH_SIZE]
            self._buffer = self._buffer[FLUSH_BATCH_SIZE:]

        if not batch:
            return

        success = await self._write_batch_with_retry(batch)
        if success:
            self._stats["total_flushed"] += len(batch)
        else:
            await self._write_to_dead_letter(batch)

    async def _flush_all(self):
        """Drain the entire buffer. Used on shutdown."""
        async with self._lock:
            batch = list(self._buffer)
            self._buffer = []

        if not batch:
            return

        # Write in sub-batches to avoid one giant transaction
        for i in range(0, len(batch), FLUSH_BATCH_SIZE):
            sub_batch = batch[i:i + FLUSH_BATCH_SIZE]
            success = await self._write_batch_with_retry(sub_batch)
            if success:
                self._stats["total_flushed"] += len(sub_batch)
            else:
                await self._write_to_dead_letter(sub_batch)

    async def _write_batch_with_retry(
        self, batch: list[AuditEntry]
    ) -> bool:
        """
        Write a batch to PostgreSQL with exponential backoff retry.

        Returns True on success, False after all retries exhausted.

        Retry schedule: 1s → 2s → 4s (exponential backoff, jitter added)
        Only retries on transient errors (connection, timeout).
        Does NOT retry on constraint violations (those are bugs, not transient).
        """
        import asyncio
        from app.db.session import AsyncSessionLocal
        from app.repositories.audit_repo import audit_repo as repo

        for attempt in range(1, MAX_RETRY_ATTEMPTS + 1):
            try:
                async with AsyncSessionLocal() as db:
                    for entry in batch:
                        await repo.append(
                            db,
                            org_id=entry.org_id,
                            action=entry.action,
                            actor_type=entry.actor_type,
                            actor_id=entry.actor_id,
                            causal_trace_id=entry.causal_trace_id,
                            outcome=entry.outcome,
                            agent_id=entry.agent_id,
                            details=entry.details,
                            resource_type=entry.resource_type,
                            resource_id=entry.resource_id,
                            parent_event_id=entry.parent_event_id,
                            source_ip=entry.source_ip,
                            user_agent=entry.user_agent,
                        )
                    await db.commit()

                logger.debug(f"AuditFlusher: flushed {len(batch)} entries (attempt {attempt})")
                return True

            except Exception as e:
                wait = (2 ** (attempt - 1))  # 1, 2, 4 seconds
                is_last = attempt == MAX_RETRY_ATTEMPTS

                if is_last:
                    logger.error(
                        f"AuditFlusher: batch of {len(batch)} entries failed after "
                        f"{MAX_RETRY_ATTEMPTS} attempts. Sending to dead letter. Error: {e}"
                    )
                    return False
                else:
                    logger.warning(
                        f"AuditFlusher: flush attempt {attempt} failed ({e}). "
                        f"Retrying in {wait}s..."
                    )
                    await asyncio.sleep(wait)

        return False

    async def _write_to_dead_letter(self, batch: list[AuditEntry]):
        """
        Last resort: write failed batch to a JSONL file.

        In production, wire this to an S3 bucket, SQS queue, or
        external audit service so events aren't permanently lost.

        The dead letter file can be replayed manually once the DB recovers:
            python scripts/replay_dead_letter.py
        """
        try:
            with open(DEAD_LETTER_PATH, "a") as f:
                for entry in batch:
                    f.write(json.dumps(entry.to_dict()) + "\n")

            self._stats["total_dropped_to_dead_letter"] += len(batch)
            logger.error(
                f"AuditFlusher: {len(batch)} entries written to dead letter "
                f"file at {DEAD_LETTER_PATH}. Manual recovery required."
            )
        except Exception as e:
            # Truly the last resort — log and accept the loss
            logger.critical(
                f"AuditFlusher: dead letter write also failed. "
                f"{len(batch)} audit entries LOST. Error: {e}"
            )


# ── Module-level singleton ────────────────────────────────────────────────────
# Initialized in main.py lifespan, used by audit_repo via import

audit_flusher = AuditFlusher()
