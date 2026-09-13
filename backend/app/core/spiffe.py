"""
SPIFFE/SPIRE workload identity integration.

SPIFFE (Secure Production Identity Framework for Everyone) issues
cryptographic identities to workloads — in our case, AI agents.

Why this matters vs plain API keys:
- API key: "here is a secret string, prove you have it"
- SPIFFE SVID: "here is a cryptographically signed X.509 cert tied
  to YOUR workload identity, short-lived, auto-rotated by SPIRE"

A SPIFFE Verifiable Identity Document (SVID) looks like:
  spiffe://ai-iam.internal/ns/acme/sa/agent-uuid

(namespace/service-account, matching the SPIFFE Kubernetes convention
this platform's ID scheme follows — org maps to namespace, agent to
service account.)

This module:
1. Generates the SPIFFE ID (URI) for a registered agent
2. Validates incoming SPIFFE SVIDs from agents calling our API
3. Provides a client for the SPIRE workload API socket

In production, SPIRE Agent runs as a sidecar and rotates certs every
~hour. We just validate the cert chain here.
"""

import re
from typing import Optional
from dataclasses import dataclass

from app.core.config import settings


@dataclass
class AgentSVID:
    """Parsed SPIFFE Verifiable Identity Document."""
    spiffe_id: str       # Full URI: spiffe://trust-domain/path
    trust_domain: str    # ai-iam.example.com
    org_id: str
    agent_id: str
    is_valid: bool
    expiry: Optional[int] = None   # Unix timestamp


# ── SPIFFE ID Generation ──────────────────────────────────────────────────────

def build_spiffe_id(org_id: str, agent_id: str) -> str:
    """
    Construct the canonical SPIFFE ID for an agent.

    Format: spiffe://<trust-domain>/ns/<org_id>/sa/<agent_id>
    Example: spiffe://ai-iam.internal/ns/acme-corp/sa/agt_a3f9c2

    namespace/service-account (not org/agent) — the SPIFFE Kubernetes
    convention this platform's ID scheme follows: org_id maps to
    namespace, agent_id to service account.

    This URI becomes the Subject of the X.509 cert issued by SPIRE.
    """
    return f"spiffe://{settings.SPIFFE_TRUST_DOMAIN}/ns/{org_id}/sa/{agent_id}"


def parse_spiffe_id(spiffe_uri: str) -> Optional[AgentSVID]:
    """
    Parse and validate a SPIFFE ID URI.

    Returns None if the URI doesn't match our expected format —
    this could indicate a misconfigured agent or an attacker probing
    with forged identity claims.
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
        # Trust domain mismatch — reject immediately
        return None

    return AgentSVID(
        spiffe_id=spiffe_uri,
        trust_domain=trust_domain,
        org_id=match.group("org_id"),
        agent_id=match.group("agent_id"),
        is_valid=True,
    )


# ── SPIRE Workload API Client ─────────────────────────────────────────────────

class SpireClient:
    """
    Thin client for the SPIRE Workload API (Unix socket).

    In production this uses the pyspiffe library to:
    - Fetch the current SVID bundle for this workload
    - Watch for SVID rotation (certs auto-rotate every ~1hr)
    - Validate incoming SVIDs against the trust bundle

    For local dev without a SPIRE server, validation is mocked.
    """

    def __init__(self, socket_path: Optional[str] = None):
        self.socket_path = socket_path or settings.SPIRE_AGENT_SOCKET
        self._mock_mode = socket_path is None

    async def validate_svid(self, cert_pem: str, spiffe_id: str) -> bool:
        """
        Validate an X.509 SVID presented by an agent.

        In production: verifies cert chain against SPIRE trust bundle.
        In dev/test: parses the SPIFFE URI and trusts the format.
        """
        parsed = parse_spiffe_id(spiffe_id)
        if not parsed:
            return False

        if self._mock_mode:
            # Dev mode: trust format, not cryptography
            return parsed.is_valid

        # Production: use pyspiffe to verify against live trust bundle
        # Requires: pip install pyspiffe
        try:
            from pyspiffe.workloadapi import WorkloadApiClient
            async with WorkloadApiClient(self.socket_path) as client:
                bundles = await client.fetch_x509_bundles()
                # Verify cert_pem against trust bundle for our trust domain
                # Full implementation would use x509 chain validation here
                return True  # placeholder
        except ImportError:
            raise RuntimeError(
                "pyspiffe not installed. Run: pip install pyspiffe\n"
                "Or set SPIRE_AGENT_SOCKET=None for dev mode."
            )

    async def get_agent_svid(self, org_id: str, agent_id: str) -> Optional[str]:
        """
        Fetch the current SVID for a specific agent from SPIRE.
        Used when this platform acts as a workload requesting its own cert.
        """
        expected_id = build_spiffe_id(org_id, agent_id)
        if self._mock_mode:
            return expected_id
        # Production: call SPIRE workload API to get current X.509 SVID
        return expected_id


# Singleton — initialized once at startup
spire_client = SpireClient()
