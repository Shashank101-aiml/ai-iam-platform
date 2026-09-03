"""
Role Pydantic v2 schemas.
Handles role definitions and assignment requests for AI agents.
"""

from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class RoleBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    description: Optional[str] = Field(None, max_length=255)
    scopes: List[str] = Field(default_factory=list)


class RoleCreate(RoleBase):
    pass


class RoleUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    description: Optional[str] = Field(None, max_length=255)
    scopes: Optional[List[str]] = None


class RoleResponse(RoleBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    org_id: str
    created_at: datetime
    updated_at: datetime


class AgentRoleAssignRequest(BaseModel):
    agent_id: str
    role_id: str
