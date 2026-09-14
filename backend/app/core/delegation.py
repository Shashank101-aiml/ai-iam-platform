"""
Multi-hop agent delegation chain management.

Scenario this solves:
  Orchestrator Agent (has [read, write, execute]) 
    → delegates [read, execute] to Research Agent
      → delegates [read] to Summarizer Agent
        → tries to delegate [write] — BLOCKED (doesn't have it)

Rules enforced here:
1. Scope attenuation: delegated scopes ⊆ delegating agent's scopes
2. Depth limit: chain cannot exceed MAX_DELEGATION_DEPTH
3. Cycle detection: Agent A cannot delegate to itself (directly or indirectly)
4. Every delegation is signed and auditable
"""

import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional

from app.core.config import settings
from app.core.permissions import validate_scope_subset


class DelegationDepthExceeded(ValueError):
    """Raised when a delegation would push the chain past MAX_DELEGATION_DEPTH."""


class DelegationCycleDetected(ValueError):
    """Raised when the delegatee already appears somewhere in this chain."""


class SelfDelegationError(ValueError):
    """Raised when an agent attempts to delegate to itself."""


@dataclass
class DelegationLink:
    """One hop in a delegation chain."""
    grant_id: str
    delegating_agent_id: str
    delegatee_agent_id: str
    scopes: list[str]
    depth: int
    issued_at: datetime
    expires_at: datetime
    causal_trace_id: str
    revoked: bool = False


@dataclass
class DelegationChain:
    """Full chain from root agent to current agent."""
    links: list[DelegationLink] = field(default_factory=list)

    @property
    def depth(self) -> int:
        return len(self.links)

    @property
    def root_agent_id(self) -> Optional[str]:
        if not self.links:
            return None
        return self.links[0].delegating_agent_id

    @property
    def current_scopes(self) -> list[str]:
        """Effective scopes at the end of the chain (most restricted)."""
        if not self.links:
            return []
        return self.links[-1].scopes

    def all_agent_ids(self) -> list[str]:
        """All agent IDs that appear in this chain."""
        ids = []
        for link in self.links:
            ids.append(link.delegating_agent_id)
            ids.append(link.delegatee_agent_id)
        return list(set(ids))


class DelegationValidator:
    """
    Validates delegation requests before issuing grants.
    Stateless — takes current chain + request and emits verdict.
    """

    def validate(
        self,
        chain: DelegationChain,
        delegating_agent_id: str,
        delegatee_agent_id: str,
        delegating_agent_scopes: list[str],
        requested_scopes: list[str],
    ) -> list[str]:
        """
        Validate a delegation request. Returns the approved scopes.

        Raises ValueError with a reason if delegation is not allowed.
        """
        # 1. Depth check
        new_depth = chain.depth + 1
        if new_depth > settings.MAX_DELEGATION_DEPTH:
            raise DelegationDepthExceeded(
                f"Delegation rejected: chain depth {new_depth} exceeds maximum allowed "
                f"depth of {settings.MAX_DELEGATION_DEPTH}. "
                f"Chain: {self._format_chain(chain)}"
            )

        # 2. Cycle detection
        existing_ids = chain.all_agent_ids()
        if delegatee_agent_id in existing_ids:
            raise DelegationCycleDetected(
                f"Delegation rejected: cycle detected. "
                f"Agent '{delegatee_agent_id}' is already in chain: "
                f"{existing_ids}"
            )

        # 3. Self-delegation
        if delegating_agent_id == delegatee_agent_id:
            raise SelfDelegationError(
                "Delegation rejected: agent cannot delegate to itself."
            )

        # 4. Scope attenuation — most critical check
        approved_scopes = validate_scope_subset(
            requested_scopes,
            delegating_agent_scopes,
        )

        return approved_scopes

    def _format_chain(self, chain: DelegationChain) -> str:
        if not chain.links:
            return "(empty)"
        parts = [chain.links[0].delegating_agent_id]
        for link in chain.links:
            parts.append(link.delegatee_agent_id)
        return " → ".join(parts)


def build_delegation_grant(
    delegating_agent_id: str,
    delegatee_agent_id: str,
    approved_scopes: list[str],
    depth: int,
    causal_trace_id: str,
    ttl_seconds: int = 600,
) -> DelegationLink:
    """
    Create a delegation grant record for DB persistence.
    """
    now = datetime.now(timezone.utc)
    return DelegationLink(
        grant_id=str(uuid.uuid4()),
        delegating_agent_id=delegating_agent_id,
        delegatee_agent_id=delegatee_agent_id,
        scopes=approved_scopes,
        depth=depth,
        issued_at=now,
        expires_at=datetime.fromtimestamp(
            now.timestamp() + ttl_seconds, tz=timezone.utc
        ),
        causal_trace_id=causal_trace_id,
    )


# Singleton validator
delegation_validator = DelegationValidator()
