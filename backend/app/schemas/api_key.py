"""
API Key Pydantic v2 schemas.
Handles API key issuance requests and response structures, ensuring plaintext keys
are only transmitted once upon creation or rotation.
"""

from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field
from app.core.constants import CredentialType


class ApiKeyIssueRequest(BaseModel):
    scopes: List[str] = Field(default_factory=list)
    ttl_days: int = Field(default=90, ge=1, le=365)


class ApiKeyIssueResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    key_id: str
    key_hint: str
    plaintext_key: str = Field(..., description="Plaintext secret — returned exactly once upon issuance or rotation.")
    scopes: List[str]
    expires_at: Optional[datetime] = None
    created_at: datetime


class ApiKeyRotateResponse(BaseModel):
    old_key_id: str
    new_key: ApiKeyIssueResponse
    grace_period_hours: int
    grace_period_expires_at: datetime


class ApiKeySummaryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    key_id: str
    key_hint: str
    scopes: List[str]
    is_active: bool
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    use_count: int
    rotated_at: Optional[datetime] = None
    credential_type: str = CredentialType.API_KEY
    created_at: datetime
