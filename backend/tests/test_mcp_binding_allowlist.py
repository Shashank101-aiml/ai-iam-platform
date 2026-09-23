"""
SSRF allowlist for mcp_bindings[].server_url, enforced at agent registration.

Since POST /auth/trial-signup lets anyone become an operator of their own
org, a binding's server_url can no longer be trusted just because an
"operator" wrote it — without this check a visitor could register an agent
bound to an internal service (postgres, redis, opa, cloud metadata) and have
the MCP proxy POST /tools/<name> to it from inside the network.
"""

import pytest
from httpx import AsyncClient
from app.models.organization import Organization


def _register(client: AsyncClient, token: str, bindings):
    return client.post(
        "/api/v1/agents",
        headers={"Authorization": token},
        json={"name": "Bound Agent", "allowed_scopes": ["tool:execute"], "mcp_bindings": bindings},
    )


@pytest.mark.asyncio
async def test_allowed_host_binding_is_accepted(
    client: AsyncClient, operator_token: str, test_org: Organization
):
    response = await _register(
        client, operator_token,
        [{"server_id": "data-mcp", "server_url": "http://mock-mcp:8080", "tool_filter": ["query_database"]}],
    )
    assert response.status_code == 201, response.text
    assert response.json()["mcp_bindings"][0]["server_url"] == "http://mock-mcp:8080"


@pytest.mark.asyncio
async def test_host_match_is_case_insensitive(
    client: AsyncClient, operator_token: str, test_org: Organization
):
    response = await _register(
        client, operator_token, [{"server_id": "x", "server_url": "http://MOCK-MCP:8080"}]
    )
    assert response.status_code == 201, response.text


@pytest.mark.asyncio
async def test_no_bindings_and_binding_without_url_still_register(
    client: AsyncClient, operator_token: str, test_org: Organization
):
    assert (await _register(client, operator_token, [])).status_code == 201
    # A binding with no server_url already fails cleanly at call time, not here.
    assert (await _register(client, operator_token, [{"server_id": "no-url"}])).status_code == 201


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "server_url",
    [
        "http://postgres:5432",
        "http://redis:6379",
        "http://opa:8181",
        "http://localhost:8000",
        "http://169.254.169.254/latest/meta-data",
        "http://mock-mcp.evil.com:8080",
        "http://mock-mcp@evil.com",
        "http://mock-mcp:pw@evil.com",
        "ftp://mock-mcp:8080",
        "file:///etc/passwd",
        "not a url",
        "http://",
    ],
)
async def test_disallowed_binding_urls_are_rejected(
    client: AsyncClient, operator_token: str, test_org: Organization, server_url: str
):
    response = await _register(client, operator_token, [{"server_id": "bad", "server_url": server_url}])
    assert response.status_code == 422, f"{server_url!r} -> {response.status_code} {response.text}"
    assert "bad" in response.text  # names the offending binding


@pytest.mark.asyncio
async def test_one_bad_binding_rejects_the_whole_registration(
    client: AsyncClient, operator_token: str, test_org: Organization
):
    response = await _register(
        client, operator_token,
        [
            {"server_id": "ok", "server_url": "http://mock-mcp:8080"},
            {"server_id": "bad", "server_url": "http://postgres:5432"},
        ],
    )
    assert response.status_code == 422
    listing = await client.get("/api/v1/agents", headers={"Authorization": operator_token})
    assert listing.status_code == 200
    assert listing.json() == []  # nothing half-registered
