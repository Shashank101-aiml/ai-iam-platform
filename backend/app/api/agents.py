"""
Agents API Router.
Manages the two-phase lifecycle (`PENDING` → `ACTIVE` → `SUSPENDED` → `DECOMMISSIONED`),
SPIFFE attestation, and JIT activation.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, status, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.agent import (
    AgentCreate,
    AgentActivateRequest,
    AgentJitActivateRequest,
    AgentStatusUpdate,
    AgentResponse,
)
from app.services.agent_service import agent_service
from app.repositories.agent_repo import agent_repo
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
    from fastapi import HTTPException
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
