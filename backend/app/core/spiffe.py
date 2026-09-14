"""
SPIFFE-style agent identifiers.

HONEST SCOPE (Slice 16): this module does NOT perform SPIFFE/SPIRE
workload attestation. There is no SPIRE server, no X.509 SVID, no cert
chain, and nothing here is cryptographically verified against a trust
bundle. What actually exists is a SPIFFE-shaped URI string —

    spiffe://<trust-domain>/ns/<org_id>/sa/<agent_id>

— used purely as a structured, collision-resistant, human-readable
identifier (org maps to namespace, agent to service account, matching
the SPIFFE Kubernetes convention for readability/interop with tooling
that expects this shape). parse_spiffe_id validates that FORMAT and
trust-domain match; it proves nothing about who is presenting it.

The actual cryptographic trust boundary in this platform is the RS256
JWT (see core/jwt.py) issued at token exchange — that's what's signed,
short-lived, and verified on every request. This module's job ends at
generating and format-checking an identifier string that gets carried
inside that JWT and the database, nothing more.

Wiring a real SPIRE deployment (a running SPIRE server/agent,
pyspiffe-based X.509 SVID fetch and chain validation, automatic
rotation) is a genuine, separate infrastructure project — deliberately
out of scope here. What was in scope, and is what this rewrite fixes:
the code no longer claims to do that verification when it doesn't. An
earlier version of validate_svid() had an unreachable "production"
branch that silently `return True` after fetching (and never actually
checking) a trust bundle — dead code (nothing in this codebase ever
constructs SpireClient in non-mock mode), but exactly the kind of
placeholder that reads as real verification to anyone skimming it.
"""

import re
from typing import Optional
from dataclasses import dataclass

from app.core.config import settings


@dataclass
class AgentSVID:
    """A parsed, format-checked SPIFFE-style identifier — not a verified credential."""
    spiffe_id: str       # Full URI: spiffe://trust-domain/path
    trust_domain: str
    org_id: str
    agent_id: str
    is_valid: bool


# ── SPIFFE-style ID generation ────────────────────────────────────────────────

def build_spiffe_id(org_id: str, agent_id: str) -> str:
    """
    Construct this agent's canonical SPIFFE-style identifier.

    Format: spiffe://<trust-domain>/ns/<org_id>/sa/<agent_id>
    Example: spiffe://ai-iam.internal/ns/acme-corp/sa/agt_a3f9c2

    namespace/service-account (not org/agent) — the SPIFFE Kubernetes
    convention this platform's ID scheme follows: org_id maps to
    namespace, agent_id to service account.

    This is a STRING IDENTIFIER, not a certificate subject — no X.509
    cert is issued for it (see module docstring).
    """
    return f"spiffe://{settings.SPIFFE_TRUST_DOMAIN}/ns/{org_id}/sa/{agent_id}"


def parse_spiffe_id(spiffe_uri: str) -> Optional[AgentSVID]:
    """
    Parse a SPIFFE-style identifier and check its FORMAT and trust
    domain. Returns None if the URI doesn't match the expected shape or
    names a different trust domain.

    This is a syntax/namespace check, not an authentication decision —
    it proves the string is well-formed, not that whoever presented it
    is who it claims to be. The RS256 JWT (core/jwt.py) is what's
    actually verified on every request.
    """
    pattern = (
        r"^spiffe://(?P<trust_domain>[^/]+)"
        r"/ns/(?P<org_id>[^/]+)"
        r"/sa/(?P<agent_id>[^/]+)$"
    )
    match = re.match(pattern, spiffe_uri)
    if not match:
        return None

    trust_domain = match.group("trust_domain")
    if trust_domain != settings.SPIFFE_TRUST_DOMAIN:
        return None

    return AgentSVID(
        spiffe_id=spiffe_uri,
        trust_domain=trust_domain,
        org_id=match.group("org_id"),
        agent_id=match.group("agent_id"),
        is_valid=True,
    )


# ── SpireClient ────────────────────────────────────────────────────────────
#
# Named for interface familiarity with a real deployment (see module
# docstring), not because it talks to SPIRE — it does not. Kept as a
# separate class, rather than inlining these two calls at their call
# site in agent_service.py, so a future real SPIRE integration has one
# clear seam to replace, without every caller needing to change.

class SpireClient:
    """Resolves and format-checks this platform's SPIFFE-style identifiers. Performs no attestation — see module docstring."""

    async def validate_svid(self, spiffe_id: str) -> bool:
        """
        True if `spiffe_id` is a well-formed identifier for THIS trust
        domain. NOT a cryptographic verification of anything — there is
        no certificate here to validate a chain for.
        """
        parsed = parse_spiffe_id(spiffe_id)
        return parsed is not None and parsed.is_valid

    async def get_agent_svid(self, org_id: str, agent_id: str) -> str:
        """Return the canonical identifier for (org_id, agent_id) — see build_spiffe_id."""
        return build_spiffe_id(org_id, agent_id)


# Singleton — initialized once at startup
spire_client = SpireClient()
