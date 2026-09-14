"""
Token Exchange Pydantic v2 schemas.
Facilitates credential exchange requests (`api_key` or `spiffe_svid`) into short-lived RS256 JWTs.
"""

from typing import Optional, List
from pydantic import BaseModel, Field


class TokenIntent(BaseModel):
    """
    Optional task-scoping hint on /token/exchange (Slice 12, RFC 9396).
    When present, the minted token is bound to exactly this one
    (mcp_server_id, tool_name) pair — see core/jwt.py's
    authorization_details claim. Omit entirely for a session-scoped
    token (the pre-Slice-12 default), unless the requested scopes fall
    under settings.MCP_TASK_SCOPING_REQUIRED_SCOPES, in which case
    omitting this is refused rather than silently widened.
    """
    mcp_server_id: str = Field(..., min_length=1)
    tool_name: str = Field(..., min_length=1)


class TokenExchangeRequest(BaseModel):
    grant_type: str = Field(..., description="Either 'api_key' or 'spiffe_svid'")
    credential: str = Field(..., description="The raw API key ('aiiam_...') or SVID token string")
    causal_trace_id: Optional[str] = None
    intent: Optional[TokenIntent] = None


class AgentJwtResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    jti: str
    scopes: List[str]
    causal_trace_id: str
    delegation_depth: int = 0
    on_behalf_of: Optional[str] = None
    authorization_details: Optional[List[dict]] = None


class TokenInspectResponse(BaseModel):
    valid: bool
    payload: Optional[dict] = None
    error: Optional[str] = None
