"""
Slice 16 test: SpireClient performs format-checking only, never claims attestation.

Locks in the Slice 16 fix — validate_svid used to have an unreachable
"production" branch that fetched (and ignored) a SPIRE trust bundle,
then unconditionally `return True`. Nothing in this codebase ever
constructed SpireClient in a mode that reached it, but it read as real
cryptographic verification to anyone skimming the code. There is now
exactly one code path, and it does exactly what its docstring says:
format/trust-domain checking, nothing more.
"""

import pytest

from app.core.spiffe import spire_client, build_spiffe_id, parse_spiffe_id
from app.core.config import settings


@pytest.mark.asyncio
async def test_validate_svid_accepts_well_formed_id_for_this_trust_domain():
    spiffe_id = build_spiffe_id("acme-corp", "agt-123")
    assert await spire_client.validate_svid(spiffe_id) is True


@pytest.mark.asyncio
async def test_validate_svid_rejects_malformed_id():
    assert await spire_client.validate_svid("not-a-spiffe-uri") is False


@pytest.mark.asyncio
async def test_validate_svid_rejects_a_different_trust_domain():
    forged = f"spiffe://attacker.example/ns/acme-corp/sa/agt-123"
    assert await spire_client.validate_svid(forged) is False


@pytest.mark.asyncio
async def test_get_agent_svid_returns_the_same_identifier_build_spiffe_id_does():
    """No SPIRE round-trip happens — this is a pure, deterministic format resolution."""
    resolved = await spire_client.get_agent_svid("acme-corp", "agt-123")
    assert resolved == build_spiffe_id("acme-corp", "agt-123")


def test_parse_spiffe_id_round_trips_through_build_spiffe_id():
    spiffe_id = build_spiffe_id("acme-corp", "agt-123")
    parsed = parse_spiffe_id(spiffe_id)
    assert parsed is not None
    assert parsed.org_id == "acme-corp"
    assert parsed.agent_id == "agt-123"
    assert parsed.trust_domain == settings.SPIFFE_TRUST_DOMAIN
