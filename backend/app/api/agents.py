"""
Agents API Router.
Manages the two-phase lifecycle (`PENDING` → `ACTIVE` → `SUSPENDED` → `DECOMMISSIONED`),
SPIFFE attestation, and JIT activation.
"""

from typing import List
from fastapi import APIRouter, Depends, status, Request, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.agent import (
    AgentCreate,
    AgentJitActivateRequest,
    AgentStatusUpdate,
    AgentResponse,
)
from app.schemas.api_key import ApiKeyIssueRequest, ApiKeyIssueResponse, ApiKeySummaryResponse
from app.schemas.on_behalf_of import (
    OnBehalfOfGrantCreate,
    OnBehalfOfGrantRevokeRequest,
    OnBehalfOfGrantResponse,
)
from app.services.agent_service import agent_service
from app.services.api_key_service import api_key_service
from app.repositories.agent_repo import agent_repo
from app.repositories.api_key_repo import api_key_repo
from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter()


@router.post("", response_model=AgentResponse, status_code=status.HTTP_201_CREATED)
async def register_agent(
    agent_in: AgentCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Register a new AI agent identity in PENDING state."""
    agent = await agent_service.register(
        db,
        org_id=current_user.org_id,
        name=agent_in.name,
        description=agent_in.description,
        allowed_scopes=agent_in.allowed_scopes,
        mcp_bindings=agent_in.mcp_bindings,
        parent_agent_id=agent_in.parent_agent_id,
        is_ephemeral=agent_in.is_ephemeral,
        ephemeral_ttl_seconds=3600 if agent_in.is_ephemeral else None,
        actor_id=f"user:{current_user.id}",
        source_ip=request.client.host if request.client else None,
    )
    await db.commit()
    await db.refresh(agent)
    return agent


@router.post("/{agent_id}/activate", response_model=AgentResponse)
async def activate_agent(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Provision workload identity via SPIRE and activate agent (`ACTIVE`)."""
    agent = await agent_service.activate(
        db,
        agent_id=agent_id,
        org_id=current_user.org_id,
        actor_id=f"user:{current_user.id}",
        activated_by_user_id=current_user.id,
        source_ip=request.client.host if request.client else None,
    )
    await db.commit()
    await db.refresh(agent)
    return agent


@router.post("/{agent_id}/jit-activate", response_model=AgentResponse)
async def jit_activate_agent(
    agent_id: str,
    jit_in: AgentJitActivateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Just-In-Time activation for ephemeral sub-agents with strict task TTL."""
    agent = await agent_service.jit_activate(
        db,
        agent_id=agent_id,
        org_id=current_user.org_id,
        task_id=jit_in.task_id,
        ttl_seconds=jit_in.ttl_seconds,
    )
    await db.commit()
    await db.refresh(agent)
    return agent


@router.post("/{agent_id}/suspend", response_model=AgentResponse)
async def suspend_agent(
    agent_id: str,
    status_in: AgentStatusUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Temporarily suspend an active agent identity."""
    agent = await agent_service.suspend(
        db,
        agent_id=agent_id,
        org_id=current_user.org_id,
        reason=status_in.reason or "Suspended via API",
        actor_id=f"user:{current_user.id}",
        source_ip=request.client.host if request.client else None,
    )
    await db.commit()
    await db.refresh(agent)
    return agent


@router.post("/{agent_id}/decommission", response_model=AgentResponse)
async def decommission_agent(
    agent_id: str,
    status_in: AgentStatusUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Irreversibly decommission an agent, revoking all keys and sealing audit logs."""
    agent = await agent_service.decommission(
        db,
        agent_id=agent_id,
        org_id=current_user.org_id,
        reason=status_in.reason or "Decommissioned via API",
        actor_id=f"user:{current_user.id}",
        source_ip=request.client.host if request.client else None,
    )
    await db.commit()
    await db.refresh(agent)
    return agent


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Inspect specific agent details."""
    agent = await agent_repo.get_by_id_and_org(db, agent_id, current_user.org_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@router.get("", response_model=List[AgentResponse])
async def list_agents(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all agents across the operator's organization."""
    return await agent_repo.list_by_org(db, current_user.org_id, skip=skip, limit=limit)


@router.post("/{agent_id}/keys", response_model=ApiKeyIssueResponse, status_code=status.HTTP_201_CREATED)
async def issue_agent_key(
    agent_id: str,
    key_in: ApiKeyIssueRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Issue a new API key (`aiiam_...`) for an active agent in the operator's own org."""
    result = await api_key_service.issue_key(
        db,
        agent_id=agent_id,
        org_id=current_user.org_id,
        scopes=key_in.scopes,
        ttl_days=key_in.ttl_days,
        actor_id=f"user:{current_user.id}",
        source_ip=request.client.host if request.client else None,
    )
    await db.commit()
    return result


@router.get("/{agent_id}/keys", response_model=List[ApiKeySummaryResponse])
async def list_agent_keys(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all API keys belonging to an agent in the operator's own org."""
    agent = await agent_repo.get_by_id_and_org(db, agent_id, current_user.org_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return await api_key_repo.get_all_keys_for_agent(db, agent_id)


@router.post(
    "/{agent_id}/on-behalf-of-grants",
    response_model=OnBehalfOfGrantResponse,
    status_code=status.HTTP_201_CREATED,
)
async def grant_on_behalf_of(
    agent_id: str,
    grant_in: OnBehalfOfGrantCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Vouch that this agent's tokens should carry the CALLING operator's
    own authority, for the given scopes, for ttl_seconds — distinct
    from agent-to-agent delegation and from (doesn't overwrite) the
    agent's permanent activated_by_user_id. See
    agent_service.resolve_on_behalf_of for how this is consulted at
    token-mint time.
    """
    grant = await agent_service.grant_on_behalf_of(
        db,
        agent_id=agent_id,
        org_id=current_user.org_id,
        granted_by_user_id=current_user.id,
        scopes=grant_in.scopes,
        ttl_seconds=grant_in.ttl_seconds,
        actor_id=f"user:{current_user.id}",
    )
    await db.commit()
    return grant


@router.post("/{agent_id}/on-behalf-of-grants/{grant_id}/revoke", status_code=status.HTTP_200_OK)
async def revoke_on_behalf_of(
    agent_id: str,
    grant_id: str,
    revoke_in: OnBehalfOfGrantRevokeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Immediately revoke an on-behalf-of grant."""
    await agent_service.revoke_on_behalf_of(
        db,
        grant_id=grant_id,
        org_id=current_user.org_id,
        actor_id=f"user:{current_user.id}",
        reason=revoke_in.reason,
    )
    await db.commit()
    return {"grant_id": grant_id, "revoked": True}
