"""
Agent Pydantic v2 schemas.
Encompasses registration requests, SPIFFE activation, JIT ephemeral requests,
and agent profile representation.
"""

from typing import Optional, List, Any, Dict
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field
from app.core.constants import AgentStatus


class AgentCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    allowed_scopes: List[str] = Field(default_factory=list)
    mcp_bindings: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    parent_agent_id: Optional[str] = None
    max_delegation_depth: int = Field(default=3, ge=1, le=10)
    is_ephemeral: bool = False
    decommission_at: Optional[datetime] = None


class AgentActivateRequest(BaseModel):
    spiffe_id: str = Field(..., min_length=10, max_length=512)


class AgentJitActivateRequest(BaseModel):
    task_id: str
    ttl_seconds: int = Field(default=3600, ge=60, le=86400)
    allowed_scopes: Optional[List[str]] = None


class AgentStatusUpdate(BaseModel):
    status: AgentStatus
    reason: Optional[str] = None


class AgentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    org_id: str
    name: str
    description: Optional[str] = None
    status: str
    spiffe_id: Optional[str] = None
    parent_agent_id: Optional[str] = None
    max_delegation_depth: int
    is_ephemeral: bool
    decommission_at: Optional[datetime] = None
    allowed_scopes: List[str]
    mcp_bindings: Optional[List[Dict[str, Any]]] = None
    created_at: datetime
    updated_at: datetime
