"""
Audit Log Pydantic v2 schemas.
Enables query filtering, individual event retrieval, causal tree reconstruction,
and cryptographic hash chain integrity reports.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class AuditLogQueryFilter(BaseModel):
    agent_id: Optional[str] = None
    action: Optional[str] = None
    outcome: Optional[str] = None
    causal_trace_id: Optional[str] = None
    skip: int = Field(default=0, ge=0)
    limit: int = Field(default=50, ge=1, le=500)


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    org_id: str
    agent_id: Optional[str] = None
    action: str
    details: Optional[Dict[str, Any]] = None
    actor_type: str
    actor_id: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    outcome: str
    causal_trace_id: str
    parent_event_id: Optional[str] = None
    entry_hash: str
    previous_hash: str
    sequence_number: int
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: datetime


class CausalTraceNode(AuditLogResponse):
    children: List["CausalTraceNode"] = Field(default_factory=list)


class CausalTraceTreeResponse(BaseModel):
    causal_trace_id: str
    root_events: List[CausalTraceNode]
    total_events: int


class IntegrityVerificationReport(BaseModel):
    org_id: str
    chain_valid: bool
    broken_at_sequence: Optional[int] = None
    total_entries_checked: int
    verified_at: datetime
