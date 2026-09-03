"""
Delegation Service — manages agent-to-agent trust grants.

The core security guarantee: scope attenuation.
A delegating agent can ONLY grant scopes it currently holds.
An agent with [read] cannot delegate [write].

This prevents privilege escalation through the delegation chain.

Full flow:
  1. Orchestrator (has [read, execute]) calls delegate()
  2. We fetch orchestrator's current active scopes from its JWT
  3. We validate requested scopes are a subset
  4. We check delegation depth against MAX_DELEGATION_DEPTH
  5. We detect cycles (agent A → B → A is invalid)
  6. We issue a delegation token (short-lived JWT)
  7. We persist the DelegationGrant for audit and revocation
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status

from app.models.delegation_grant import DelegationGrant
from app.core.constants import AuditAction, TokenType
from app.core.delegation import (
    delegation_validator,
    build_delegation_grant,
    DelegationChain,
    DelegationLink,
)
from app.core.jwt import create_delegation_token
from app.core.config import settings
from app.repositories.agent_repo import agent_repo
from app.repositories.audit_repo import audit_repo


class DelegationService:

    async def delegate(
        self,
        db: AsyncSession,
        *,
        delegating_agent_id: str,
        delegatee_agent_id: str,
        org_id: str,
        requested_scopes: list[str],
        delegating_agent_scopes: list[str],  # From the delegating agent's JWT
        current_chain: Optional[DelegationChain] = None,
        causal_trace_id: Optional[str] = None,
        ttl_seconds: int = 600,
    ) -> dict:
        """
        Issue a delegation grant from one agent to another.

        Returns:
        - delegation_token: JWT the delegatee uses to act on behalf of delegator
        - grant_id: DB record ID for revocation
        - approved_scopes: what was actually granted (may be subset of requested)
        """
        if not causal_trace_id:
            causal_trace_id = str(uuid.uuid4())

        chain = current_chain or DelegationChain()

        # Validate agents exist and belong to org
        delegating_agent = await agent_repo.get_by_id_and_org(
            db, delegating_agent_id, org_id
        )
        if not delegating_agent:
            raise HTTPException(status_code=404, detail="Delegating agent not found")

        delegatee_agent = await agent_repo.get_by_id_and_org(
            db, delegatee_agent_id, org_id
        )
        if not delegatee_agent:
            raise HTTPException(status_code=404, detail="Delegatee agent not found")

        from app.core.constants import AgentStatus
        if delegatee_agent.status != AgentStatus.ACTIVE:
            raise HTTPException(
                status_code=422,
                detail=f"Delegatee agent is not ACTIVE (status: {delegatee_agent.status})"
            )

        # Run validation: depth, cycles, scope attenuation
        try:
            approved_scopes = delegation_validator.validate(
                chain=chain,
                delegating_agent_id=delegating_agent_id,
                delegatee_agent_id=delegatee_agent_id,
                delegating_agent_scopes=delegating_agent_scopes,
                requested_scopes=requested_scopes,
            )
        except ValueError as e:
            await audit_repo.append(
                db,
                org_id=org_id,
                action=AuditAction.DELEGATION_GRANTED,
                actor_type="agent",
                actor_id=delegating_agent_id,
                agent_id=delegating_agent_id,
                causal_trace_id=causal_trace_id,
                outcome="failure",
                details={"error": str(e), "requested_scopes": requested_scopes},
            )
            raise HTTPException(status_code=403, detail=str(e))

        current_depth = chain.depth + 1

        # Issue the delegation JWT
        token_result = create_delegation_token(
            delegating_agent_id=delegating_agent_id,
            delegatee_agent_id=delegatee_agent_id,
            org_id=org_id,
            scopes=[],  # Import PermissionScope properly in real usage
            causal_trace_id=causal_trace_id,
            current_depth=current_depth - 1,
        )

        # Persist the grant for audit + revocation tracking
        grant = DelegationGrant(
            id=str(uuid.uuid4()),
            org_id=org_id,
            delegating_agent_id=delegating_agent_id,
            delegatee_agent_id=delegatee_agent_id,
            scopes=approved_scopes,
            delegation_depth=current_depth,
            delegation_jti=token_result["jti"],
            is_active=True,
            expires_at=datetime.fromtimestamp(token_result["exp"], tz=timezone.utc),
            causal_trace_id=causal_trace_id,
        )
        db.add(grant)
        await db.flush()
        await db.refresh(grant)

        await audit_repo.append(
            db,
            org_id=org_id,
            action=AuditAction.DELEGATION_GRANTED,
            actor_type="agent",
            actor_id=delegating_agent_id,
            agent_id=delegating_agent_id,
            causal_trace_id=causal_trace_id,
            outcome="success",
            details={
                "grant_id": grant.id,
                "delegatee_agent_id": delegatee_agent_id,
                "approved_scopes": approved_scopes,
                "delegation_depth": current_depth,
                "expires_at": grant.expires_at.isoformat(),
            },
        )

        return {
            "delegation_token": token_result["token"],
            "grant_id": grant.id,
            "approved_scopes": approved_scopes,
            "delegation_depth": current_depth,
            "expires_at": grant.expires_at,
            "delegatee_agent_id": delegatee_agent_id,
        }

    async def revoke_grant(
        self,
        db: AsyncSession,
        *,
        grant_id: str,
        org_id: str,
        actor_id: str,
        reason: str,
    ) -> bool:
        """
        Revoke a delegation grant immediately.

        Note: The delegation JWT will still be cryptographically valid
        until it expires. True revocation requires a JTI blacklist
        (Redis in production). Here we mark the DB grant as revoked,
        which the delegation auth middleware checks.
        """
        from sqlalchemy import update, select
        from app.models.delegation_grant import DelegationGrant as DG

        result = await db.execute(
            select(DG).where(DG.id == grant_id, DG.org_id == org_id)
        )
        grant = result.scalar_one_or_none()
        if not grant:
            raise HTTPException(status_code=404, detail="Delegation grant not found")

        now = datetime.now(timezone.utc)
        await db.execute(
            update(DG)
            .where(DG.id == grant_id)
            .values(
                is_active=False,
                revoked_at=now,
                revocation_reason=reason,
            )
        )
        await db.flush()

        await audit_repo.append(
            db,
            org_id=org_id,
            action=AuditAction.DELEGATION_REVOKED,
            actor_type="user",
            actor_id=actor_id,
            agent_id=grant.delegating_agent_id,
            causal_trace_id=str(uuid.uuid4()),
            outcome="success",
            details={
                "grant_id": grant_id,
                "delegatee_agent_id": grant.delegatee_agent_id,
                "reason": reason,
            },
        )
        return True

    async def get_active_grants_for_agent(
        self,
        db: AsyncSession,
        agent_id: str,
        org_id: str,
    ) -> list[DelegationGrant]:
        """Return all active grants where this agent is the delegatee."""
        from sqlalchemy import select, and_
        from app.models.delegation_grant import DelegationGrant as DG

        now = datetime.now(timezone.utc)
        result = await db.execute(
            select(DG).where(
                and_(
                    DG.delegatee_agent_id == agent_id,
                    DG.org_id == org_id,
                    DG.is_active == True,
                    DG.expires_at > now,
                )
            )
        )
        return result.scalars().all()


delegation_service = DelegationService()
