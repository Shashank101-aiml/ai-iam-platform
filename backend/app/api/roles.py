"""
Roles API Router.
Manages RBAC role definitions and assigns roles (`scopes`) to AI agents.
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.role import RoleCreate, RoleResponse, AgentRoleAssignRequest
from app.repositories.role_repo import role_repo
from app.repositories.agent_repo import agent_repo
from app.models.role import Role
from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter()


@router.post("", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
async def create_role(
    role_in: RoleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new role definition within the organization."""
    import uuid
    role = Role(
        id=str(uuid.uuid4()),
        org_id=current_user.org_id,
        name=role_in.name,
        description=role_in.description,
        scopes=role_in.scopes,
    )
    await role_repo.create(db, role)
    await db.commit()
    return role


@router.get("", response_model=List[RoleResponse])
async def list_roles(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all roles in the organization."""
    return await role_repo.list_by_org(db, current_user.org_id)


@router.post("/assign", status_code=status.HTTP_200_OK)
async def assign_role_to_agent(
    assign_in: AgentRoleAssignRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Assign a role and its scopes to an AI agent."""
    agent = await agent_repo.get_by_id_and_org(db, assign_in.agent_id, current_user.org_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    role = await role_repo.get_by_id(db, assign_in.role_id)
    if not role or role.org_id != current_user.org_id:
        raise HTTPException(status_code=404, detail="Role not found")

    await role_repo.assign_to_agent(db, agent_id=assign_in.agent_id, role_id=assign_in.role_id)
    
    # Also merge scopes into agent.allowed_scopes if desired
    merged = list(set(agent.allowed_scopes + role.scopes))
    agent.allowed_scopes = merged
    await db.commit()
    return {"status": "assigned", "agent_id": assign_in.agent_id, "role_id": assign_in.role_id}
