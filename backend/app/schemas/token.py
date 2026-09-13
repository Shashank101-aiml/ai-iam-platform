"""
Token Exchange Pydantic v2 schemas.
Facilitates credential exchange requests (`api_key` or `spiffe_svid`) into short-lived RS256 JWTs.
"""

from typing import Optional, List
from pydantic import BaseModel, Field


class TokenExchangeRequest(BaseModel):
    grant_type: str = Field(..., description="Either 'api_key' or 'spiffe_svid'")
    credential: str = Field(..., description="The raw API key ('aiiam_...') or SVID token string")
    causal_trace_id: Optional[str] = None


class AgentJwtResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    jti: str
    scopes: List[str]
    causal_trace_id: str
    delegation_depth: int = 0
    on_behalf_of: Optional[str] = None


class TokenInspectResponse(BaseModel):
    valid: bool
    payload: Optional[dict] = None
    error: Optional[str] = None
