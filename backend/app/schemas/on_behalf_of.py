"""On-Behalf-Of Grant Pydantic v2 schemas (Slice 11)."""

from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class OnBehalfOfGrantCreate(BaseModel):
    scopes: List[str] = Field(..., min_length=1)
    ttl_seconds: int = Field(default=7200, ge=60, le=86400)


class OnBehalfOfGrantRevokeRequest(BaseModel):
    reason: str = Field(default="Revoked by operator", min_length=1, max_length=255)


class OnBehalfOfGrantResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    org_id: str
    agent_id: str
    granted_by_user_id: str
    scopes: List[str]
    is_active: bool
    expires_at: datetime
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[str] = None
    created_at: datetime
