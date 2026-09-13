"""
Delegation Service — manages agent-to-agent trust grants.

The core security guarantee: scope attenuation.
A delegating agent can ONLY grant scopes it currently holds.
An agent with [read] cannot delegate [write].

This prevents privilege escalation through the delegation chain.

Full flow:
  1. Orchestrator (has [read, execute]) calls delegate()
  2. We resolve the orchestrator's current scopes server-side, from its
     own verified access/delegation token — never from a caller-supplied
     parameter — intersected with the agent's current allowed_scopes as
     a defense-in-depth ceiling in case allowed_scopes was tightened
     after the token was minted
  3. We walk the REAL delegation lineage from the database (via
     parent_grant_id, not a client-trusted depth counter) to build the
     chain depth/cycle checks actually need
  4. We validate requested scopes are a subset
  5. We check delegation depth against MAX_DELEGATION_DEPTH
  6. We detect cycles (agent A → B → A is invalid)
  7. We issue a delegation token (short-lived JWT) carrying the real
     approved scopes
  8. We persist the DelegationGrant, linked to its parent, for audit,
     revocation, and the next hop's chain walk
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException

from app.models.delegation_grant import DelegationGrant
from app.core.constants import AuditAction, AgentStatus, PermissionScope
from app.core.delegation import (
    delegation_validator,
    DelegationChain,
    DelegationLink,
)
from app.core.permissions import ScopeAttenuationError
from app.core.jwt import create_delegation_token
from app.core.revocation import track_issued_jti, revoke_jti, revoke_all_in_index
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
        delegating_agent_verified_scopes: list[str],
        delegating_agent_jti: Optional[str] = None,
        parent_trace_id: Optional[str] = None,
        ttl_seconds: int = 600,
        on_behalf_of: Optional[str] = None,
    ) -> dict:
        """
        Issue a delegation grant from one agent to another.

        delegating_agent_verified_scopes must come from the delegating
        agent's own verified JWT claims (request.state.agent["scopes"])
        — never from a request body field the caller controls, or scope
        attenuation is just the client self-reporting its privileges.

        on_behalf_of, likewise, must come from the delegating agent's
        own verified token claims (request.state.agent["on_behalf_of"])
        — never re-resolved here and never caller-supplied. Delegation
        propagates the human anchor unchanged down the chain; it never
        grants a NEW one a delegatee wouldn't otherwise have (Slice 11).

        delegating_agent_jti (also from the verified token) is how the
        real chain gets reconstructed: it's matched against
        DelegationGrant.delegation_jti to find the grant that gave this
        agent its own authority, then walked back to the root via
        parent_grant_id. If no such grant exists, the agent is acting on
        its own root access token and originates a new chain (depth 0).

        Returns delegation_token, jti, expires_in, scopes, delegation_depth,
        and the persisted grant — matching DelegationTokenResponse exactly.
        """
        causal_trace_id = parent_trace_id or str(uuid.uuid4())

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

        if delegatee_agent.status != AgentStatus.ACTIVE:
            raise HTTPException(
                status_code=422,
                detail=f"Delegatee agent is not ACTIVE (status: {delegatee_agent.status})"
            )

        try:
            chain, parent_grant_id = await self._load_chain(
                db, delegating_agent_jti=delegating_agent_jti
            )
        except ValueError as e:
            await audit_repo.append(
                org_id=org_id,
                action=AuditAction.DELEGATION_GRANTED,
                actor_type="agent",
                actor_id=delegating_agent_id,
                agent_id=delegating_agent_id,
                causal_trace_id=causal_trace_id,
                outcome="failure",
                details={"error": str(e)},
            )
            raise HTTPException(status_code=403, detail=str(e))

        # Ceiling, not source of truth: a stale token can't regain scopes
        # allowed_scopes no longer includes.
        delegating_agent_scopes = list(
            set(delegating_agent_verified_scopes) & set(delegating_agent.allowed_scopes or [])
        )

        try:
            approved_scopes = delegation_validator.validate(
                chain=chain,
                delegating_agent_id=delegating_agent_id,
                delegatee_agent_id=delegatee_agent_id,
                delegating_agent_scopes=delegating_agent_scopes,
                requested_scopes=requested_scopes,
            )
        except ScopeAttenuationError as e:
            await audit_repo.append(
                org_id=org_id,
                action=AuditAction.DELEGATION_GRANTED,
                actor_type="agent",
                actor_id=delegating_agent_id,
                agent_id=delegating_agent_id,
                causal_trace_id=causal_trace_id,
                outcome="failure",
                details={"error": str(e), "requested_scopes": requested_scopes},
            )
            raise HTTPException(status_code=422, detail=str(e))
        except ValueError as e:
            # DelegationDepthExceeded / DelegationCycleDetected / SelfDelegationError
            await audit_repo.append(
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

        new_depth = chain.depth + 1

        # Real scopes, not []: the delegatee's token must actually carry
        # what it was approved for.
        token_scopes = []
        for s in approved_scopes:
            try:
                token_scopes.append(PermissionScope(s))
            except ValueError:
                pass

        token_result = create_delegation_token(
            delegating_agent_id=delegating_agent_id,
            delegatee_agent_id=delegatee_agent_id,
            org_id=org_id,
            scopes=token_scopes,
            causal_trace_id=causal_trace_id,
            current_depth=chain.depth,
            on_behalf_of=on_behalf_of,
        )

        grant = DelegationGrant(
            id=str(uuid.uuid4()),
            org_id=org_id,
            delegating_agent_id=delegating_agent_id,
            delegatee_agent_id=delegatee_agent_id,
            scopes=approved_scopes,
            delegation_depth=new_depth,
            delegation_jti=token_result["jti"],
            parent_grant_id=parent_grant_id,
            is_active=True,
            expires_at=datetime.fromtimestamp(token_result["exp"], tz=timezone.utc),
            causal_trace_id=causal_trace_id,
        )
        db.add(grant)
        await db.flush()
        await db.refresh(grant)

        # Reverse index for cascade revoke — suspending/decommissioning
        # the delegatee needs to find this token to blacklist it.
        # revoke_grant() itself doesn't need this: it already has the
        # grant's own delegation_jti column directly.
        await track_issued_jti(
            f"agent:{delegatee_agent_id}:jtis", token_result["jti"], token_result["exp"]
        )

        await audit_repo.append(
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
                "delegation_depth": new_depth,
                "expires_at": grant.expires_at.isoformat(),
                "on_behalf_of": on_behalf_of,
            },
        )

        return {
            "delegation_token": token_result["token"],
            "jti": token_result["jti"],
            "expires_in": token_result["expires_in"],
            "scopes": approved_scopes,
            "delegation_depth": new_depth,
            "grant": grant,
            "on_behalf_of": on_behalf_of,
        }

    async def _load_chain(
        self, db: AsyncSession, *, delegating_agent_jti: Optional[str]
    ) -> tuple[DelegationChain, Optional[str]]:
        """
        Walk parent_grant_id pointers from the grant that authorized the
        delegating agent's current token, up to the root, building the
        real ancestor chain from persisted state — not a value the
        caller could simply assert.

        Returns (chain, immediate_parent_grant_id). immediate_parent_grant_id
        is what the new grant being created should record as ITS OWN
        parent_grant_id, continuing the lineage for the next hop.

        Raises ValueError if the grant that authorized this agent (or
        any ancestor of it) has been revoked — a delegation can't proceed
        through a broken link in its own lineage, even before Slice 9's
        JTI-blacklist makes already-issued downstream tokens stop working
        immediately rather than at their natural expiry.
        """
        if not delegating_agent_jti:
            return DelegationChain(), None

        result = await db.execute(
            select(DelegationGrant).where(
                DelegationGrant.delegation_jti == delegating_agent_jti
            )
        )
        own_grant = result.scalar_one_or_none()
        if not own_grant:
            # Acting on a root access token, not a delegation token —
            # this agent originates a new chain.
            return DelegationChain(), None

        if not own_grant.is_active:
            raise ValueError(
                f"Delegation rejected: the grant that authorized this agent "
                f"(grant_id={own_grant.id}) has been revoked."
            )

        ancestors: list[DelegationGrant] = [own_grant]
        visited_ids = {own_grant.id}
        current = own_grant
        while current.parent_grant_id:
            if current.parent_grant_id in visited_ids:
                break  # malformed data — never loop forever
            result = await db.execute(
                select(DelegationGrant).where(
                    DelegationGrant.id == current.parent_grant_id
                )
            )
            parent = result.scalar_one_or_none()
            if not parent:
                break
            if not parent.is_active:
                raise ValueError(
                    f"Delegation rejected: an ancestor grant (grant_id={parent.id}) "
                    f"in this chain has been revoked."
                )
            ancestors.append(parent)
            visited_ids.add(parent.id)
            current = parent

        ancestors.reverse()  # root-first order
        links = [
            DelegationLink(
                grant_id=g.id,
                delegating_agent_id=g.delegating_agent_id,
                delegatee_agent_id=g.delegatee_agent_id,
                scopes=g.scopes,
                depth=g.delegation_depth,
                issued_at=g.created_at,
                expires_at=g.expires_at,
                causal_trace_id=g.causal_trace_id,
                revoked=not g.is_active,
            )
            for g in ancestors
        ]
        return DelegationChain(links=links), own_grant.id

    async def revoke_grant(
        self,
        db: AsyncSession,
        *,
        grant_id: str,
        org_id: str,
        actor_id: str,
        reason: str,
    ) -> dict:
        """
        Revoke a delegation grant immediately — and cascade.

        Since Slice 5, any FURTHER delegation attempted through this
        grant (or through any grant descending from it) was already
        blocked at the next hop — _load_chain refuses to build a chain
        through a revoked ancestor. What that alone didn't do: stop a
        token ALREADY issued from this grant (or any descendant grant)
        from continuing to work until it naturally expires. This walks
        every descendant of grant_id (parent_grant_id, forward this
        time — see _find_descendant_ids), marks each one inactive in
        the same way, and blacklists each one's delegation_jti in the
        revocation index — so a child grant one hop down stops working
        immediately too, not just at its next attempted re-delegation.
        """
        from sqlalchemy import update, select
        from app.models.delegation_grant import DelegationGrant as DG

        result = await db.execute(
            select(DG).where(DG.id == grant_id, DG.org_id == org_id)
        )
        grant = result.scalar_one_or_none()
        if not grant:
            raise HTTPException(status_code=404, detail="Delegation grant not found")

        descendant_ids = await self._find_descendant_ids(db, grant_id)
        all_ids = [grant_id] + descendant_ids

        now = datetime.now(timezone.utc)
        await db.execute(
            update(DG)
            .where(DG.id.in_(all_ids))
            .values(
                is_active=False,
                revoked_at=now,
                revocation_reason=reason,
            )
        )
        await db.flush()

        result = await db.execute(
            select(DG.delegation_jti, DG.expires_at).where(DG.id.in_(all_ids))
        )
        for jti, expires_at in result.all():
            remaining = int((expires_at - now).total_seconds())
            if remaining > 0:
                await revoke_jti(jti, remaining)

        await audit_repo.append(
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
                "descendant_grants_revoked": len(descendant_ids),
            },
        )
        return {
            "grant_id": grant_id,
            "revoked": True,
            "descendant_grants_revoked": len(descendant_ids),
            "reason": reason,
        }

    async def _find_descendant_ids(self, db: AsyncSession, grant_id: str) -> list[str]:
        """
        Every grant descending from grant_id, walking parent_grant_id
        FORWARD (children, not ancestors — the opposite direction from
        _load_chain). Iterative breadth-first rather than a recursive
        CTE: the depth ceiling (MAX_DELEGATION_DEPTH) already bounds
        this to a handful of round trips at most, and it keeps the
        query plain and easy to reason about.
        """
        from sqlalchemy import select
        from app.models.delegation_grant import DelegationGrant as DG

        descendants: list[str] = []
        frontier = [grant_id]
        while frontier:
            result = await db.execute(
                select(DG.id).where(DG.parent_grant_id.in_(frontier))
            )
            children = [row[0] for row in result.all()]
            if not children:
                break
            descendants.extend(children)
            frontier = children
        return descendants

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
