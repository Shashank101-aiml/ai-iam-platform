"""
Delegation Grant Pydantic v2 schemas.
Defines requests for multi-hop agent-to-agent delegation grants and token exchange DTOs.
"""

from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class DelegationCreateRequest(BaseModel):
    delegatee_agent_id: str
    requested_scopes: List[str] = Field(..., min_length=1)
    ttl_seconds: int = Field(default=600, ge=60, le=3600)
    causal_trace_id: Optional[str] = None


class DelegationGrantResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    org_id: str
    delegating_agent_id: str
    delegatee_agent_id: str
    scopes: List[str]
    delegation_depth: int
    delegation_jti: str
    is_active: bool
    expires_at: datetime
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[str] = None
    causal_trace_id: str
    parent_grant_id: Optional[str] = None
    created_at: datetime


class DelegationRevokeRequest(BaseModel):
    reason: str = Field(default="Revoked by operator or delegating agent", min_length=1, max_length=255)


class DelegationRevokeResponse(BaseModel):
    grant_id: str
    revoked: bool
    descendant_grants_revoked: int
    reason: str


class DelegationTokenResponse(BaseModel):
    delegation_token: str
    jti: str
    expires_in: int
    scopes: List[str]
    delegation_depth: int
    grant: DelegationGrantResponse
    on_behalf_of: Optional[str] = None
