"""
MCP Session Pydantic v2 schemas.
Defines execution requests for Model Context Protocol (MCP) tools and responses
including privacy-preserving argument/result hashes.
"""

from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class McpToolExecuteRequest(BaseModel):
    # mcp_server_url is deliberately NOT a field here — the proxy resolves
    # it server-side from the calling agent's own mcp_bindings by
    # mcp_server_id. Accepting a URL from the caller would let any
    # authenticated agent point the proxy's outbound request at an
    # arbitrary address (SSRF), with the proxy's own network reachability.
    mcp_server_id: str = Field(..., min_length=1)
    arguments: Dict[str, Any] = Field(default_factory=dict)
    causal_trace_id: Optional[str] = None


class McpToolExecuteResponse(BaseModel):
    session_id: str
    tool_name: str
    status: str
    result: Any
    args_hash: str
    result_hash: str
    duration_ms: int
    policy_decision: str


class McpSessionLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    org_id: str
    agent_id: str
    mcp_server_id: str
    mcp_server_url: str
    tool_name: str
    args_hash: Optional[str] = None
    result_hash: Optional[str] = None
    args_metadata: Optional[Dict[str, Any]] = None
    status: str
    error_code: Optional[str] = None
    duration_ms: Optional[int] = None
    policy_decision: str
    blocking_reason: Optional[str] = None
    source_untrusted: bool = False
    causal_trace_id: str
    created_at: datetime
