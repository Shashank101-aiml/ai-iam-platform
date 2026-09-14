"""
Agent Service — lifecycle management for AI agent identities.

Lifecycle states:
  PENDING → ACTIVE → SUSPENDED → DECOMMISSIONED

Key operations:
1. register(): Create agent record, validate config
2. provision(): Assign SPIFFE workload identity (SPIRE integration)
3. activate(): Move PENDING → ACTIVE, issue initial credentials
4. suspend(): Temporarily disable without deleting state
5. decommission(): Permanent shutdown, revoke all credentials, seal audit trail
6. jit_activate(): Just-in-Time activation for ephemeral agents — they exist
   for exactly one task run, then auto-decommission

Every state transition is audited before the DB write, not after.
This ensures the audit log is never missing an event even if the
subsequent DB operation fails.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status

from app.models.agent import Agent
from app.core.constants import AgentStatus, AuditAction
from app.core.spiffe import build_spiffe_id, spire_client
from app.core.revocation import revoke_all_in_index
from app.repositories.agent_repo import agent_repo
from app.repositories.audit_repo import audit_repo


class AgentService:

    async def register(
        self,
        db: AsyncSession,
        *,
        org_id: str,
        name: str,
        description: Optional[str],
        allowed_scopes: list[str],
        mcp_bindings: Optional[list[dict]],
        parent_agent_id: Optional[str],
        is_ephemeral: bool,
        ephemeral_ttl_seconds: Optional[int],
        actor_id: str,
        source_ip: Optional[str] = None,
    ) -> Agent:
        """
        Register a new agent. Starts in PENDING status.
        A separate activate() call provisions credentials and moves to ACTIVE.

        Two-phase design rationale: registration captures intent and
        validates config; activation triggers credential issuance and
        external SPIRE calls. Separating them lets us fail fast on bad
        config before any external side-effects happen.
        """
        causal_trace_id = str(uuid.uuid4())

        # Validate parent agent exists and belongs to same org
        if parent_agent_id:
            parent = await agent_repo.get_by_id_and_org(db, parent_agent_id, org_id)
            if not parent:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Parent agent '{parent_agent_id}' not found in org '{org_id}'"
                )
            if parent.status not in (AgentStatus.ACTIVE, AgentStatus.PENDING):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Parent agent is {parent.status} — cannot register child"
                )

        agent = Agent(
            id=str(uuid.uuid4()),
            org_id=org_id,
            name=name,
            description=description,
            status=AgentStatus.PENDING,
            allowed_scopes=allowed_scopes,
            mcp_bindings=mcp_bindings or [],
            parent_agent_id=parent_agent_id,
            is_ephemeral=is_ephemeral,
            decommission_at=(
                datetime.now(timezone.utc) + timedelta(seconds=ephemeral_ttl_seconds)
                if is_ephemeral and ephemeral_ttl_seconds
                else None
            ),
        )

        # Audit BEFORE the DB write — if the write fails, audit still exists
        await audit_repo.append(
            org_id=org_id,
            action=AuditAction.AGENT_REGISTERED,
            actor_type="user",
            actor_id=actor_id,
            agent_id=agent.id,
            causal_trace_id=causal_trace_id,
            outcome="success",
            details={
                "agent_name": name,
                "is_ephemeral": is_ephemeral,
                "parent_agent_id": parent_agent_id,
                "allowed_scopes": allowed_scopes,
            },
            source_ip=source_ip,
        )

        saved_agent = await agent_repo.create(db, agent)
        return saved_agent

    async def activate(
        self,
        db: AsyncSession,
        *,
        agent_id: str,
        org_id: str,
        actor_id: str,
        activated_by_user_id: str,
        source_ip: Optional[str] = None,
    ) -> Agent:
        """
        Provision workload identity and activate the agent.

        1. Validates agent is in PENDING state
        2. Calls SPIRE to get a SPIFFE ID assigned (workload identity)
        3. Moves agent to ACTIVE
        4. Records activated_by_user_id — the permanent human-authority
           anchor for this agent's root tokens (Slice 11; see
           models/agent.py's docstring and resolve_on_behalf_of below)
        5. Emits audit event
        """
        causal_trace_id = str(uuid.uuid4())

        agent = await agent_repo.get_by_id_and_org(db, agent_id, org_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        if agent.status != AgentStatus.PENDING:
            raise HTTPException(
                status_code=422,
                detail=f"Agent must be PENDING to activate. Current: {agent.status}"
            )

        # Assign this agent's SPIFFE-style identifier. No SPIRE server is
        # involved and nothing here is attested — see core/spiffe.py's
        # module docstring. spire_client.get_agent_svid() returns the
        # same value build_spiffe_id() does; kept as a separate call so
        # a real SPIRE integration has one seam to replace later.
        spiffe_id = build_spiffe_id(org_id, agent_id)
        await spire_client.get_agent_svid(org_id, agent_id)

        # Update state
        await agent_repo.set_spiffe_id(db, agent_id, spiffe_id)
        await agent_repo.update_status(db, agent_id, AgentStatus.ACTIVE)
        await agent_repo.set_activated_by(db, agent_id, activated_by_user_id)

        await audit_repo.append(
            org_id=org_id,
            action=AuditAction.AGENT_ACTIVATED,
            actor_type="user",
            actor_id=actor_id,
            agent_id=agent_id,
            causal_trace_id=causal_trace_id,
            outcome="success",
            details={"spiffe_id": spiffe_id, "activated_by_user_id": activated_by_user_id},
            source_ip=source_ip,
        )

        await db.refresh(agent)
        return agent

    async def resolve_on_behalf_of(
        self, db: AsyncSession, *, agent: Agent, requested_scopes: list[str]
    ) -> Optional[str]:
        """
        Which human operator's authority a NEW token for this agent
        should carry, if any. Called at every token-mint site
        (api/token.py's /exchange, api/oauth.py's /token) — never
        caller-supplied.

        An active, unexpired OnBehalfOfGrant whose scopes cover the
        request takes precedence over the agent's permanent
        activated_by_user_id — a grant is how an operator can vouch for
        a DIFFERENT human's authority than whoever originally activated
        the agent, bounded and revocable, without touching that
        permanent record. Falls back to activated_by_user_id, then
        None (no human anchor at all — a legitimate state, not a gap
        to paper over with a fabricated value).
        """
        from app.repositories.on_behalf_of_grant_repo import on_behalf_of_grant_repo

        grants = await on_behalf_of_grant_repo.get_active_for_agent(db, agent.id)
        requested = set(requested_scopes)
        for grant in grants:
            if requested <= set(grant.scopes):
                return grant.granted_by_user_id
        return agent.activated_by_user_id

    async def grant_on_behalf_of(
        self,
        db: AsyncSession,
        *,
        agent_id: str,
        org_id: str,
        granted_by_user_id: str,
        scopes: list[str],
        ttl_seconds: int,
        actor_id: str,
    ):
        """
        The "minimal grant primitive": an operator vouches that this
        agent's tokens should carry THEIR authority, for these scopes,
        for ttl_seconds — distinct from agent-to-agent delegation
        (DelegationGrant), and distinct from (doesn't overwrite) the
        agent's permanent activated_by_user_id.
        """
        from datetime import timedelta
        from app.models.on_behalf_of_grant import OnBehalfOfGrant

        agent = await agent_repo.get_by_id_and_org(db, agent_id, org_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")

        invalid_scopes = set(scopes) - set(agent.allowed_scopes or [])
        if invalid_scopes:
            raise HTTPException(
                status_code=422,
                detail=f"Requested scopes exceed agent's allowed scopes: {sorted(invalid_scopes)}"
            )

        grant = OnBehalfOfGrant(
            id=str(uuid.uuid4()),
            org_id=org_id,
            agent_id=agent_id,
            granted_by_user_id=granted_by_user_id,
            scopes=scopes,
            is_active=True,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
        )
        db.add(grant)
        await db.flush()
        await db.refresh(grant)

        await audit_repo.append(
            org_id=org_id,
            action=AuditAction.ON_BEHALF_OF_GRANTED,
            actor_type="user",
            actor_id=actor_id,
            agent_id=agent_id,
            causal_trace_id=str(uuid.uuid4()),
            outcome="success",
            details={
                "grant_id": grant.id,
                "granted_by_user_id": granted_by_user_id,
                "scopes": scopes,
                "expires_at": grant.expires_at.isoformat(),
            },
        )
        return grant

    async def revoke_on_behalf_of(
        self,
        db: AsyncSession,
        *,
        grant_id: str,
        org_id: str,
        actor_id: str,
        reason: str,
    ) -> None:
        """Immediately revoke an on-behalf-of grant — does not touch the agent's permanent activated_by_user_id."""
        from sqlalchemy import update
        from app.models.on_behalf_of_grant import OnBehalfOfGrant
        from app.repositories.on_behalf_of_grant_repo import on_behalf_of_grant_repo

        grant = await on_behalf_of_grant_repo.get_by_id_and_org(db, grant_id, org_id)
        if not grant:
            raise HTTPException(status_code=404, detail="On-behalf-of grant not found")

        now = datetime.now(timezone.utc)
        await db.execute(
            update(OnBehalfOfGrant)
            .where(OnBehalfOfGrant.id == grant_id)
            .values(is_active=False, revoked_at=now, revocation_reason=reason)
        )
        await db.flush()

        await audit_repo.append(
            org_id=org_id,
            action=AuditAction.ON_BEHALF_OF_REVOKED,
            actor_type="user",
            actor_id=actor_id,
            agent_id=grant.agent_id,
            causal_trace_id=str(uuid.uuid4()),
            outcome="success",
            details={"grant_id": grant_id, "reason": reason},
        )

    async def jit_activate(
        self,
        db: AsyncSession,
        *,
        agent_id: str,
        org_id: str,
        task_id: str,
        ttl_seconds: int = 300,
    ) -> Agent:
        """
        Just-in-Time activation for ephemeral agents.

        Called when an orchestrator spawns a short-lived sub-agent.
        The agent auto-decommissions after ttl_seconds regardless of
        task completion state — this is a hard safety ceiling.
        """
        causal_trace_id = f"jit:{task_id}"

        agent = await agent_repo.get_by_id_and_org(db, agent_id, org_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        if not agent.is_ephemeral:
            raise HTTPException(
                status_code=422,
                detail="JIT activation only applies to ephemeral agents"
            )

        # Override decommission time to task-scoped TTL
        new_decommission = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

        from sqlalchemy import update
        from app.models.agent import Agent as AgentModel
        await db.execute(
            update(AgentModel)
            .where(AgentModel.id == agent_id)
            .values(
                status=AgentStatus.ACTIVE,
                decommission_at=new_decommission,
                updated_at=datetime.now(timezone.utc),
            )
        )

        await audit_repo.append(
            org_id=org_id,
            action=AuditAction.AGENT_ACTIVATED,
            actor_type="system",
            actor_id="jit_activator",
            agent_id=agent_id,
            causal_trace_id=causal_trace_id,
            outcome="success",
            details={
                "activation_type": "jit",
                "task_id": task_id,
                "ttl_seconds": ttl_seconds,
                "decommission_at": new_decommission.isoformat(),
            },
        )

        await db.refresh(agent)
        return agent

    async def suspend(
        self,
        db: AsyncSession,
        *,
        agent_id: str,
        org_id: str,
        reason: str,
        actor_id: str,
        source_ip: Optional[str] = None,
    ) -> Agent:
        """Temporarily disable an agent without destroying its state."""
        causal_trace_id = str(uuid.uuid4())

        agent = await agent_repo.get_by_id_and_org(db, agent_id, org_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        if agent.status == AgentStatus.DECOMMISSIONED:
            raise HTTPException(status_code=422, detail="Cannot suspend a decommissioned agent")

        await agent_repo.update_status(db, agent_id, AgentStatus.SUSPENDED)

        # Every token this agent currently holds — access tokens from a
        # key exchange, delegation tokens received as a delegatee — stops
        # working immediately rather than at its natural expiry. Without
        # this, "suspend" would only stop NEW credential issuance while
        # anything already issued kept working for up to
        # AGENT_ACCESS_TOKEN_EXPIRE_MINUTES more.
        revoked_count = await revoke_all_in_index(f"agent:{agent_id}:jtis")

        await audit_repo.append(
            org_id=org_id,
            action=AuditAction.AGENT_SUSPENDED,
            actor_type="user",
            actor_id=actor_id,
            agent_id=agent_id,
            causal_trace_id=causal_trace_id,
            outcome="success",
            details={"reason": reason, "tokens_revoked": revoked_count},
            source_ip=source_ip,
        )

        await db.refresh(agent)
        return agent

    async def decommission(
        self,
        db: AsyncSession,
        *,
        agent_id: str,
        org_id: str,
        reason: str,
        actor_id: str,
        source_ip: Optional[str] = None,
    ) -> Agent:
        """
        Permanently decommission an agent.

        This is irreversible. Steps:
        1. Revoke all active API keys
        2. Move agent to DECOMMISSIONED
        3. Seal the audit trail (final entry)
        """
        from app.repositories.api_key_repo import api_key_repo
        causal_trace_id = str(uuid.uuid4())

        agent = await agent_repo.get_by_id_and_org(db, agent_id, org_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        if agent.status == AgentStatus.DECOMMISSIONED:
            raise HTTPException(status_code=422, detail="Agent already decommissioned")

        # 1. Revoke all credentials
        active_keys = await api_key_repo.get_active_keys_for_agent(db, agent_id)
        for key in active_keys:
            await api_key_repo.deactivate_key(db, key.key_id)
            await revoke_all_in_index(f"key:{key.key_id}:jtis")
            await audit_repo.append(
                org_id=org_id,
                action=AuditAction.CREDENTIAL_REVOKED,
                actor_type="system",
                actor_id="decommission_process",
                agent_id=agent_id,
                causal_trace_id=causal_trace_id,
                outcome="success",
                details={"key_id": key.key_id, "reason": "agent_decommissioned"},
            )

        # 2. Update status
        await agent_repo.update_status(db, agent_id, AgentStatus.DECOMMISSIONED)

        # Belt-and-suspenders on top of the per-key revocation above: any
        # token this agent holds through a path other than an active key
        # (e.g. a delegation token received as a delegatee) also stops
        # working immediately.
        revoked_count = await revoke_all_in_index(f"agent:{agent_id}:jtis")

        # 3. Final audit seal
        await audit_repo.append(
            org_id=org_id,
            action=AuditAction.AGENT_DECOMMISSIONED,
            actor_type="user",
            actor_id=actor_id,
            agent_id=agent_id,
            causal_trace_id=causal_trace_id,
            outcome="success",
            details={
                "reason": reason,
                "keys_revoked": len(active_keys),
                "tokens_revoked": revoked_count,
            },
            source_ip=source_ip,
        )

        await db.refresh(agent)
        return agent


agent_service = AgentService()
