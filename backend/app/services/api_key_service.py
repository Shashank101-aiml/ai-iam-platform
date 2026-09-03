"""
API Key Service — credential lifecycle management.

Zero-downtime rotation design:
  Old key:  aiiam_abc123...  (active=False, but grace hash stored on new key)
  New key:  aiiam_xyz789...  (active=True, stores old hash for grace window)

During the grace window (default: 1 hour), BOTH keys work.
After grace window expires, only the new key works.
This prevents production outages when rotating credentials.

Verification flow (every API request):
  1. Look up ALL active keys for the agent (should be 1, maybe 2 during rotation)
  2. bcrypt.checkpw() against each hash
  3. If match on grace hash → accept but flag as "using rotated key" in audit
  4. Record usage (last_used_at, use_count)
"""

import uuid
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status

from app.models.api_key import ApiKey
from app.core.constants import AuditAction, PermissionScope, CredentialType
from app.core.security import (
    generate_api_key,
    generate_key_id,
    verify_api_key,
    should_rotate_key,
    is_key_expired,
)
from app.core.config import settings
from app.repositories.api_key_repo import api_key_repo
from app.repositories.agent_repo import agent_repo
from app.repositories.audit_repo import audit_repo


class ApiKeyService:

    async def issue_key(
        self,
        db: AsyncSession,
        *,
        agent_id: str,
        org_id: str,
        scopes: list[str],
        ttl_days: Optional[int] = None,
        actor_id: str,
        source_ip: Optional[str] = None,
    ) -> dict:
        """
        Issue a new API key for an agent.

        Returns the plaintext key ONCE — it is never retrievable again.
        Only the bcrypt hash is stored.

        Response includes:
        - plaintext_key: show to user once, then discard
        - key_id: safe identifier for logs and UI ("kid_a3f9c2...")
        - key_hint: last 4 chars of plaintext ("...f4e2")
        - expires_at: when the key expires
        """
        causal_trace_id = str(uuid.uuid4())

        # Validate agent exists and is active in this org
        agent = await agent_repo.get_by_id_and_org(db, agent_id, org_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")

        from app.core.constants import AgentStatus
        if agent.status != AgentStatus.ACTIVE:
            raise HTTPException(
                status_code=422,
                detail=f"Can only issue keys for ACTIVE agents. Agent is {agent.status}"
            )

        # Validate requested scopes are a subset of agent's allowed scopes
        invalid_scopes = set(scopes) - set(agent.allowed_scopes)
        if invalid_scopes:
            raise HTTPException(
                status_code=422,
                detail=f"Requested scopes exceed agent's allowed scopes: {invalid_scopes}"
            )

        # Generate the key pair — plaintext for user, hash for DB
        plaintext_key, hashed_secret = generate_api_key()
        key_id = generate_key_id()
        key_hint = plaintext_key[-4:]   # Last 4 chars only — safe to display
        ttl = ttl_days or settings.API_KEY_DEFAULT_TTL_DAYS

        api_key = ApiKey(
            id=str(uuid.uuid4()),
            agent_id=agent_id,
            org_id=org_id,
            key_id=key_id,
            hashed_secret=hashed_secret,
            key_hint=key_hint,
            scopes=scopes,
            is_active=True,
            expires_at=datetime.now(timezone.utc) + timedelta(days=ttl),
            credential_type=CredentialType.API_KEY,
        )

        await api_key_repo.create(db, api_key)

        await audit_repo.append(
            db,
            org_id=org_id,
            action=AuditAction.CREDENTIAL_ISSUED,
            actor_type="user",
            actor_id=actor_id,
            agent_id=agent_id,
            causal_trace_id=causal_trace_id,
            outcome="success",
            details={
                "key_id": key_id,
                "key_hint": f"...{key_hint}",
                "scopes": scopes,
                "expires_at": api_key.expires_at.isoformat(),
            },
            source_ip=source_ip,
        )

        return {
            "id": api_key.id,
            "plaintext_key": plaintext_key,   # Show once, never again
            "key_id": key_id,
            "key_hint": f"...{key_hint}",
            "scopes": scopes,
            "expires_at": api_key.expires_at,
            "created_at": api_key.created_at,
        }

    async def verify_key(
        self,
        db: AsyncSession,
        *,
        plaintext_key: str,
        causal_trace_id: str,
        org_id: Optional[str] = None,
        source_ip: Optional[str] = None,
    ) -> Optional[dict]:
        """
        Verify an API key and return its identity context if valid.

        Two lookup paths:

        1. Compound format "kid_xxxxxxxx:aiiam_<hex>" (preferred — this
           is what /api/v1/token/exchange requires). key_id is unique
           and indexed, so this is a single row lookup plus one bcrypt
           check, and org_id isn't needed at all: the row carries its
           own org_id.
        2. A bare "aiiam_..." key plus an org_id the caller already
           has in hand (deprecated). Scans every active key in that
           org, bcrypt-checking each one — O(n) in the org's active key
           count, and every wrong guess still costs a full bcrypt
           verify against every key in the org, which is a real CPU
           exhaustion vector at any real key volume. Kept only for
           internal callers that already know the org (this is what
           tests/test_credential_rotation.py exercises); every use logs
           a warning.

        Returns:
            {
                "agent_id": str,
                "org_id": str,
                "scopes": list[str],
                "key_id": str,
                "using_grace_key": bool,  # True if using the old key during rotation
            }
        Returns None if the key is invalid, or if it's a bare key with
        no org_id to scope a scan against.
        """
        key_id, secret = self._split_compound_key(plaintext_key)
        if key_id is not None:
            return await self._verify_by_key_id(
                db, key_id, secret, causal_trace_id, source_ip
            )

        if not plaintext_key.startswith(settings.API_KEY_PREFIX):
            return None

        if org_id is None:
            logger.warning(
                "verify_key: bare API key presented with no org_id and no "
                "kid_ prefix — refusing rather than scanning every org."
            )
            return None

        logger.warning(
            "verify_key: falling back to a full org-wide key scan (org_id=%s). "
            "This is O(n) in the org's active key count and deprecated — "
            "prefix the credential with its key_id (\"kid_xxx:aiiam_...\") "
            "to use the O(1) lookup instead.",
            org_id,
        )
        return await self._verify_by_full_scan(
            db, plaintext_key, org_id, causal_trace_id, source_ip
        )

    @staticmethod
    def _split_compound_key(plaintext_key: str) -> tuple[Optional[str], str]:
        """
        Splits "kid_xxxxxxxx:aiiam_<hex>" into (key_id, secret).
        Returns (None, plaintext_key) if it isn't in that format —
        callers fall back to the full-scan path in that case.
        """
        if ":" not in plaintext_key:
            return None, plaintext_key
        key_id, _, secret = plaintext_key.partition(":")
        if not key_id.startswith("kid_") or not secret.startswith(settings.API_KEY_PREFIX):
            return None, plaintext_key
        return key_id, secret

    async def _verify_by_key_id(
        self,
        db: AsyncSession,
        key_id: str,
        plaintext_key: str,
        causal_trace_id: str,
        source_ip: Optional[str],
    ) -> Optional[dict]:
        """O(1) path: one indexed lookup, then verify against that row only."""
        key = await api_key_repo.get_by_key_id(db, key_id)
        if not key or not key.is_active:
            # No org to attribute this to — an unknown/inactive key_id
            # doesn't tell us which tenant's audit chain it belongs on.
            logger.warning("verify_key: unknown or inactive key_id presented: %s", key_id)
            return None

        return await self._match_and_record(
            db, key, plaintext_key, causal_trace_id, source_ip
        )

    async def _verify_by_full_scan(
        self,
        db: AsyncSession,
        plaintext_key: str,
        org_id: str,
        causal_trace_id: str,
        source_ip: Optional[str],
    ) -> Optional[dict]:
        """Deprecated: verify by scanning every active key in an org."""
        from sqlalchemy import select, and_
        from app.models.api_key import ApiKey as ApiKeyModel

        result = await db.execute(
            select(ApiKeyModel).where(
                and_(
                    ApiKeyModel.org_id == org_id,
                    ApiKeyModel.is_active == True,
                )
            )
        )
        keys = result.scalars().all()

        for key in keys:
            matched = await self._match_and_record(
                db, key, plaintext_key, causal_trace_id, source_ip, record_denial_on_miss=False
            )
            if matched:
                return matched

        # No match anywhere in the org — log denied access
        await audit_repo.append(
            db,
            org_id=org_id,
            action=AuditAction.ACCESS_DENIED,
            actor_type="unknown",
            actor_id="unknown",
            causal_trace_id=causal_trace_id,
            outcome="failure",
            details={"reason": "invalid_api_key"},
            source_ip=source_ip,
        )
        return None

    async def _match_and_record(
        self,
        db: AsyncSession,
        key: ApiKey,
        plaintext_key: str,
        causal_trace_id: str,
        source_ip: Optional[str],
        record_denial_on_miss: bool = True,
    ) -> Optional[dict]:
        """
        Checks plaintext_key against one ApiKey row's primary hash, then
        its grace-period hash. On a match, records usage and an audit
        entry and returns the identity dict verify_key promises. On a
        miss, optionally audits ACCESS_DENIED against that row's own
        org (record_denial_on_miss=False when the caller — the
        full-scan path — will do this once for the whole org instead of
        once per row it happened to check).
        """
        if is_key_expired(key.expires_at):
            return None

        if verify_api_key(plaintext_key, key.hashed_secret):
            grace_key = False
        elif (
            key.previous_hashed_secret
            and key.previous_key_expires_at
            and not is_key_expired(key.previous_key_expires_at)
            and verify_api_key(plaintext_key, key.previous_hashed_secret)
        ):
            grace_key = True
        else:
            if record_denial_on_miss:
                await audit_repo.append(
                    db,
                    org_id=key.org_id,
                    action=AuditAction.ACCESS_DENIED,
                    actor_type="unknown",
                    actor_id="unknown",
                    causal_trace_id=causal_trace_id,
                    outcome="failure",
                    details={"reason": "invalid_api_key", "key_id": key.key_id},
                    source_ip=source_ip,
                )
            return None

        await api_key_repo.record_usage(db, key.key_id)
        details = {"key_id": key.key_id, "grace_key": grace_key}
        if grace_key:
            details["warning"] = "client_using_rotated_key"
        await audit_repo.append(
            db,
            org_id=key.org_id,
            action=AuditAction.CREDENTIAL_USED,
            actor_type="agent",
            actor_id=key.agent_id,
            agent_id=key.agent_id,
            causal_trace_id=causal_trace_id,
            outcome="success",
            details=details,
            source_ip=source_ip,
        )
        return {
            "agent_id": key.agent_id,
            "org_id": key.org_id,
            "scopes": key.scopes,
            "key_id": key.key_id,
            "using_grace_key": grace_key,
        }

    async def rotate_key(
        self,
        db: AsyncSession,
        *,
        key_id: str,
        org_id: str,
        actor_id: str,
        grace_period_hours: int = 1,
        source_ip: Optional[str] = None,
    ) -> dict:
        """
        Zero-downtime key rotation.

        1. Issue new key
        2. Copy old hash to new key's grace slot
        3. Deactivate old key
        4. Both keys work for grace_period_hours
        """
        causal_trace_id = str(uuid.uuid4())

        old_key = await api_key_repo.get_by_key_id(db, key_id)
        if not old_key or old_key.org_id != org_id:
            raise HTTPException(status_code=404, detail="Key not found")
        if not old_key.is_active:
            raise HTTPException(status_code=422, detail="Key is already inactive")

        plaintext_new, hashed_new = generate_api_key()
        new_key_id = generate_key_id()
        key_hint = plaintext_new[-4:]
        grace_expires = datetime.now(timezone.utc) + timedelta(hours=grace_period_hours)

        new_key = ApiKey(
            id=str(uuid.uuid4()),
            agent_id=old_key.agent_id,
            org_id=org_id,
            key_id=new_key_id,
            hashed_secret=hashed_new,
            key_hint=key_hint,
            scopes=old_key.scopes,
            is_active=True,
            expires_at=datetime.now(timezone.utc) + timedelta(
                days=settings.API_KEY_DEFAULT_TTL_DAYS
            ),
            rotated_from_id=old_key.id,
            credential_type=CredentialType.API_KEY,
        )

        await api_key_repo.store_rotation(
            db,
            old_key_id=key_id,
            new_key=new_key,
            grace_period_hash=old_key.hashed_secret,
            grace_expires_at=grace_expires,
        )

        await audit_repo.append(
            db,
            org_id=org_id,
            action=AuditAction.CREDENTIAL_ROTATED,
            actor_type="user",
            actor_id=actor_id,
            agent_id=old_key.agent_id,
            causal_trace_id=causal_trace_id,
            outcome="success",
            details={
                "old_key_id": key_id,
                "new_key_id": new_key_id,
                "grace_period_hours": grace_period_hours,
                "grace_expires_at": grace_expires.isoformat(),
            },
            source_ip=source_ip,
        )

        return {
            "plaintext_key": plaintext_new,
            "key_id": new_key_id,
            "key_hint": f"...{key_hint}",
            "rotated_from": key_id,
            "grace_expires_at": grace_expires,
            "message": (
                f"Old key works for {grace_period_hours}h grace period. "
                "Update your agent configuration to use the new key."
            ),
        }

    async def revoke_key(
        self,
        db: AsyncSession,
        *,
        key_id: str,
        org_id: str,
        reason: str,
        actor_id: str,
        source_ip: Optional[str] = None,
    ) -> bool:
        """Immediately revoke a key — no grace period."""
        causal_trace_id = str(uuid.uuid4())

        key = await api_key_repo.get_by_key_id(db, key_id)
        if not key or key.org_id != org_id:
            raise HTTPException(status_code=404, detail="Key not found")

        await api_key_repo.deactivate_key(db, key_id)

        await audit_repo.append(
            db,
            org_id=org_id,
            action=AuditAction.CREDENTIAL_REVOKED,
            actor_type="user",
            actor_id=actor_id,
            agent_id=key.agent_id,
            causal_trace_id=causal_trace_id,
            outcome="success",
            details={"key_id": key_id, "reason": reason},
            source_ip=source_ip,
        )
        return True


api_key_service = ApiKeyService()
