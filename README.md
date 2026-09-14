# AI-IAM Platform (Auth0 for Autonomous AI Agents)

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115.0-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Open Policy Agent](https://img.shields.io/badge/OPA-ReBAC%20Policy%20Engine-7B42BC?style=for-the-badge)](https://www.openpolicyagent.org/)
[![Redis](https://img.shields.io/badge/Redis-Revocation%20Index-DC382D?style=for-the-badge&logo=redis&logoColor=white)](https://redis.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

> An identity, credential-lifecycle, ReBAC authorization, and tamper-evident audit control plane for AI agents — built and hardened across 16 dependency-ordered slices, each verified live against a real Docker stack, not just unit tests.

---

## Status

Every claim below reflects code that exists, is tested, and has been verified against a real running Docker Compose stack — not a design document. If a capability isn't built yet, it's listed under **Honestly not done** instead of implied.

**Done (Phases 0–D, Slices 1–15 of 16):**
- Boot/test harness, schema-truth CI-style check, tenant isolation, reachable agent authentication (Slices 1–4)
- Real multi-hop delegation with server-side scope attenuation, depth ceiling, and cycle detection (Slice 5)
- A real OPA/Rego policy layer — fail-closed, tested with `opa test` (Slice 6)
- MCP proxy SSRF closed, `tool_filter` enforcement, durable blocked-call logging, circuit breaker (Slice 7)
- Out-of-band, append-only, hash-chained audit log with a least-privileged Postgres role and a periodic verifier (Slice 8)
- Real Redis-backed JTI revocation, wired into every revoke path, including cascading delegation revocation (Slice 9)
- MCP OAuth 2.1 resource-server compliance — RFC 8707 Resource Indicators, RFC 9207 `iss`, discovery documents, DCR (Slice 10)
- `on_behalf_of` human-authority tracing through delegation chains (Slice 11)
- Task-scoped tokens (RFC 9396 `authorization_details`) closing the "ambient authority" gap (Slice 12)
- Provenance-aware authorization — denies high-risk actions in a causal trace that already touched untrusted content (Slice 13)
- Structured JSON logging with redaction, Prometheus metrics, a correct liveness/readiness split (Slice 14)
- CORS lockdown, Redis-backed rate limiting, worker-duplication fix, pinned images, hardened container (Slice 15)

**Honestly not done:**
- **No real SPIFFE/SPIRE attestation.** `spiffe_id` is a structured, format-checked identifier string (`spiffe://<trust-domain>/ns/<org>/sa/<agent>`) — there is no SPIRE server, no X.509 cert, no cryptographic workload attestation anywhere in this codebase. The actual cryptographic trust boundary is the RS256 JWT issued at token exchange. See `backend/app/core/spiffe.py`'s module docstring for the full explanation.
- **No dashboard login flow.** The frontend calls the real API with no mock fallback (see below) but has no login form — an operator token has to be placed in `localStorage` some other way to see real data through it.
- **No production secrets backend.** JWT/DB secrets are local volume mounts / environment variables for this repo's own docker-compose; a real deployment must inject them from Vault, a cloud KMS, or an orchestrator's native secrets store (the app refuses to boot on the known local-dev default secret outside `DEBUG` mode — see `core/jwt.py::verify_jwt_secret_not_default`).
- No high availability / multi-region, no compliance-evidence automation, no full Cross-App-Access / OIDC federation — the audit chain and delegation attenuation are the real, load-bearing pieces those would build on; the rest is a separate, later project.

---

## The Problem

In multi-agent systems (LangGraph, CrewAI, AutoGen, MCP server ecosystems), agents execute tools, touch sensitive data, and delegate to peer agents autonomously.

1. **Static human secrets.** A long-lived human API key hardcoded into an agent's environment has an unbounded blast radius if that agent is compromised or prompt-injected.
2. **Uncontrolled delegation.** If Orchestrator Agent A (`[read, write, execute]`) delegates to Sub-Agent B without real, server-verified scope attenuation, B can end up with more privilege than it was ever supposed to have.
3. **Reactive tool governance.** Logging a tool call *after* it ran is worthless if the call was `delete_database`. Authorization has to happen pre-execution.
4. **Ambient authority.** A session-scoped bearer token, once minted, is usually valid for *any* call matching its scopes for its whole lifetime — not just the one call it was issued for.
5. **The lethal trifecta.** Untrusted-content exposure + tool access + the ability to communicate externally, in the same causal chain, is how prompt injection turns into exfiltration — and almost nothing in the market ties an authorization decision to *where a chain's inputs came from*.

---

## Architecture

```mermaid
graph TD
    subgraph Identity and Token Exchange
        A[Agent] -->|API key or delegation token| B(POST /token/exchange)
        B -->|RS256 access token, 15 min TTL| A
        B -.->|optional: intent = one mcp_server_id + tool_name| B
    end

    subgraph Delegation
        A -->|delegate scopes, server-verified attenuation| D[Sub-Agent]
        D -->|jti-tracked delegation token| E[AgentAuthMiddleware]
    end

    subgraph Every request
        E -->|1. JTI revocation check - Redis, fail closed| F[Redis]
        E -->|2. RS256 signature + claims verify| G[Route handler]
    end

    subgraph MCP proxy - pre-execution
        G -->|tool call| H[MCP Proxy Service]
        H -->|resolve server_url server-side, never caller-supplied| H
        H -->|resource indicator + task-scope check| H
        H -->|provenance taint check for this causal trace| H
        H -->|ReBAC decision| I[Open Policy Agent]
        I -- deny --> J[Blocked, audited, committed immediately]
        I -- allow --> K[tool_filter check] --> L[External MCP server]
    end

    subgraph Tamper-evident audit
        H -->|hash args/results, never store raw| M[(Postgres audit_logs - INSERT-only role)]
        M -->|periodic + on-demand| N[SHA-256 chain verification]
    end

    subgraph Observability
        G -.->|structured JSON logs, redacted, causal_trace_id| O[stdout]
        H -.->|denials, delegation depth, rotations, verify duration| P[/metrics - Prometheus/]
    end
```

---

## What's actually enforced, by slice

### Identity and tokens
- RS256 JWTs for agents (asymmetric — public key verifies without a DB round-trip), HS256 for human operators. 15-minute agent access tokens, 10-minute delegation tokens.
- API keys: `aiiam_<64 hex chars>`, bcrypt-hashed, never stored in plaintext. Compound `kid_xxx:aiiam_xxx` format for O(1) lookup (an org-wide bcrypt scan was a real CPU-exhaustion vector before Slice 4).
- Zero-downtime rotation with a grace window — both the old and new key work during the transition.
- **Task-scoped tokens (Slice 12):** an optional `intent: {mcp_server_id, tool_name}` at `/token/exchange` binds a token to exactly one call. Replaying it against any other tool gets a distinct `token_not_authorized_for_action`, not a generic policy denial. Mandatory for scopes named in `MCP_TASK_SCOPING_REQUIRED_SCOPES` (`credential:rotate` by default).
- **`on_behalf_of` (Slice 11):** every agent token traces back to the human operator who activated it, or to whoever a later, revocable grant vouches for — resolved server-side, never caller-supplied.

### Delegation
- Real chain loading from `DelegationGrant.parent_grant_id`, walked from the database — not a client-trusted depth counter. `MAX_DELEGATION_DEPTH` (default 5) and cycle detection (`A → B → A`) are both enforced against that real chain.
- Scope attenuation resolved from the delegating agent's own verified JWT, intersected with its current `allowed_scopes` — a delegatee can never end up with a scope the delegator didn't actually hold at delegation time.
- Revoking a grant cascades forward through every descendant grant, blacklisting each one's JTI immediately (Slice 9) — not waiting for natural expiry.

### Policy (OPA / Rego)
- Every tool-execution decision is a real query to a running OPA instance (`backend/policies/authz.rego`), fail-closed on any timeout, connection error, or ambiguous response.
- **Provenance-aware authorization (Slice 13):** `mcp_bindings` can mark a server's results as `untrusted_source` and tag specific tools with risk categories (`external_send`, `credential_access`). If any earlier call in the same `causal_trace_id` pulled untrusted content, a later high-risk call in that trace is denied outright — a heuristic against "read untrusted content → get instructions injected → exfiltrate," not a claim to have solved prompt injection.

### MCP proxy
- `mcp_server_url` is resolved server-side from the calling agent's own `mcp_bindings`, never from the request body (closes an SSRF that was live and exploitable before Slice 7).
- Per-binding `tool_filter` allowlist enforced even when scope/policy would otherwise allow a call.
- Response size cap, per-call timeout, and a per-server circuit breaker bound the blast radius of a slow or malicious downstream MCP server.
- A blocked or errored call's session/audit rows are committed immediately inside the service — not left to a caller whose exception handling would otherwise roll them back.

### Audit log
- Every entry hash-chains to the previous one (`SHA256(previous_hash + action + details + actor_id + trace_id)`); tampering with any historical row breaks every hash after it.
- Writes go through a dedicated Postgres role with INSERT + SELECT only — no UPDATE, no DELETE, enforced by Postgres itself.
- `verify_chain` streams in batches (`yield_per`), so verifying a million-entry chain runs in fixed memory. A periodic background worker replays every org's chain and raises a `CRITICAL` log the moment one is found broken, rather than waiting for someone to call the verify endpoint.

### Standards alignment (MCP OAuth 2.1, Slice 10)
- This platform is its own spec-compliant Authorization Server: `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, `/.well-known/jwks.json`, Dynamic Client Registration (PKCE-only public clients — no client secret is ever issued), RFC 8707 Resource Indicators binding a token to one `mcp_server_id`, RFC 9207 `iss` in the redirect.

### Observability (Slice 14)
- Structured, redacted JSON logs — every line carries `causal_trace_id`; a plaintext API key accidentally logged is masked before it's ever written.
- `/metrics` (Prometheus format): generic HTTP histograms plus domain counters — denials by policy reason, a delegation-depth histogram, credential rotations, audit-chain verification duration.
- A real liveness/readiness split: `/health` never touches Postgres/OPA (a real orchestrator's liveness probe must not restart a process over a dependency blip); `/health/detailed` does, for readiness.

### Runtime hardening (Slice 15)
- CORS never combines a wildcard origin with credentials (the old config was spec-invalid and silently non-functional in every real browser).
- Redis-backed rate limiting on `/auth/login` and `/token/exchange` — a shared limit across every worker process, not a per-process counter; fails open on a Redis outage (availability, not correctness, is what a rate limiter protects).
- The credential rotator, ephemeral reaper, and audit verifier each run behind a Postgres advisory lock, so a multi-worker deployment (`--workers 4`) doesn't race itself rotating the same keys.
- Every image pinned by digest; the backend container runs read-only, non-root, with all Linux capabilities dropped.

---

## Repository layout

```text
ai-iam-platform/
├── README.md
├── backend/
│   ├── app/
│   │   ├── api/                  # organizations, agents, api_keys, audit_logs, mcp_proxy,
│   │   │                         # token, oauth, well_known, health, roles, users, auth
│   │   ├── core/                 # config, jwt, permissions (OPA client), security, spiffe,
│   │   │                         # revocation, rate_limit, worker_lock, metrics, logging_config
│   │   ├── middleware/           # agent_auth.py, trace_propagation.py
│   │   ├── models/                # Agent, ApiKey, AuditLog, DelegationGrant, McpSession,
│   │   │                         # Organization, User, OAuthClient, OnBehalfOfGrant
│   │   ├── repositories/         # one per model, plain async query layer
│   │   ├── services/             # agent, api_key, audit, auth, delegation, mcp_proxy, oauth
│   │   ├── worker/                # credential_rotator.py, audit_verifier.py
│   │   └── main.py               # lifespan startup checks, middleware, router wiring, /metrics
│   ├── alembic/versions/          # linear migration chain, 0001 → 0006
│   ├── policies/                  # authz.rego + authz_test.rego (opa test)
│   └── tests/                     # pytest, one real Postgres/OPA/Redis, not mocks-only
├── docs/                          # architecture, credential-lifecycle, delegation-chain, threat-model
├── frontend/                      # React/Vite governance dashboard — no mock data fallback (Slice 16):
│   │                              # a fetch failure renders an explicit error state, never fabricated rows
│   └── src/
├── docker/                        # docker-compose.yml, Dockerfile — the actual verified environment
└── scripts/                       # bootstrap.py, seed_db.py, generate_keys.sh
```

---

## Getting started

This project has been built and verified against Docker Compose, not a bare local Python environment — that's the setup below.

### Prerequisites
* Docker Desktop (or a Docker Engine + Compose plugin)
* An RS256 keypair for agent tokens (generated once, see Step 1)

### 1. Generate the RS256 keypair
```bash
mkdir -p backend/keys
openssl genrsa -out backend/keys/private.pem 2048
openssl rsa -in backend/keys/private.pem -outform PEM -pubout -out backend/keys/public.pem
```
`backend/keys/` is gitignored — this keypair never ends up in an image layer or a commit.

### 2. Bring up the stack
```bash
docker compose -f docker/docker-compose.yml up -d
```
This starts Postgres, OPA, Redis, and the backend (which runs its own `alembic upgrade head` and seed script on startup), plus the React dashboard on `:5173`. No manual migration step, no manual seeding — `docker compose up` from a clean volume is the tested path.

### 3. Confirm it's healthy
```bash
docker compose -f docker/docker-compose.yml ps
```
All four backend-stack services should report `healthy`. The API docs are at `http://localhost:8000/docs` (only when `DEBUG=true`, as the local-dev compose file sets); the dashboard is at `http://localhost:5173`.

### Running the test suite
```bash
docker run --rm --network docker_default \
  -v "$(pwd)/backend:/app/backend" \
  -e DATABASE_URL="postgresql+asyncpg://aiiam_user:supersecretpassword@postgres:5432/aiiam_db" \
  -e TEST_DATABASE_URL="postgresql+asyncpg://aiiam_user:supersecretpassword@postgres:5432/aiiam_test_db" \
  -e OPA_URL="http://opa:8181" \
  -e REDIS_URL="redis://redis:6379/0" \
  -w /app/backend docker-backend \
  python -m pytest tests/ -q
```
(See `.github/workflows/ci.yml` for the same thing running automatically on every pull request — pytest against a real Postgres service container, `opa test` against the real policy, plus lint/type-check/build/dependency-and-secret-scan.)

---

## API surface (selected)

| Method | Route | Description | Auth |
| :--- | :--- | :--- | :---: |
| `POST` | `/api/v1/organizations` | Bootstrap a new tenant | ❌ |
| `POST` | `/api/v1/auth/login` | Operator login → HS256 JWT | ❌ (rate-limited) |
| `POST` | `/api/v1/agents` | Register an agent identity (`PENDING`) | Operator JWT |
| `POST` | `/api/v1/agents/{id}/activate` | Assign SPIFFE-style identifier, move to `ACTIVE` | Operator JWT |
| `POST` | `/api/v1/agents/{id}/keys` | Issue a hashed API key | Operator JWT |
| `POST` | `/api/v1/agents/{id}/on-behalf-of-grants` | Vouch for a human's authority behind an agent's tokens | Operator JWT |
| `POST` | `/api/v1/token/exchange` | API key → RS256 access token (optional task-scoping `intent`) | API key (rate-limited) |
| `POST` | `/api/v1/token/delegate` | Multi-hop delegation with real scope attenuation | Agent bearer |
| `POST` | `/api/v1/token/delegations/{id}/revoke` | Revoke a grant — cascades to every descendant | Operator JWT |
| `POST` | `/api/v1/mcp/tools/{tool_name}` | Pre-execution ReBAC + provenance-aware proxy | Agent bearer |
| `GET` | `/api/v1/audit/verify` | Recompute and verify the SHA-256 hash chain | Operator JWT |
| `POST` | `/api/v1/oauth/register` | Dynamic Client Registration (RFC 7591) | Operator JWT |
| `GET` | `/api/v1/oauth/authorize` → `POST /api/v1/oauth/token` | Authorization Code + PKCE (RFC 8707 resource binding) | Operator JWT / PKCE |
| `GET` | `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, `/.well-known/jwks.json` | OAuth/MCP discovery | ❌ |
| `GET` | `/health` / `GET` | `/health/detailed` | Liveness / readiness | ❌ |
| `GET` | `/metrics` | Prometheus exposition | ❌ |

---

## Security design (STRIDE, as it actually stands)

| Threat | Attack vector | Defense actually implemented |
| :--- | :--- | :--- |
| **Spoofing** | Forged agent identity | RS256-signed, short-lived JWTs verified on every request. **Not** X.509/SPIRE attestation — see Status above. |
| **Tampering** | Rewriting audit history to hide an action | Append-only SHA-256 hash chain + a Postgres role with no UPDATE/DELETE privilege on `audit_logs`. |
| **Repudiation** | An agent denies having executed a destructive call | Every MCP call's `args_hash`/`result_hash` links to the signed JWT's `causal_trace_id` in an append-only log. |
| **Information disclosure** | A DB dump leaks credentials | API keys bcrypt-hashed (never stored plaintext); MCP tool args/results stored only as SHA-256 hashes, never raw. |
| **Denial of service** | Runaway delegation, a wedged downstream MCP server | Hard `MAX_DELEGATION_DEPTH`; per-server circuit breaker + response-size cap + timeout on the MCP proxy; Redis-backed rate limiting on unauthenticated bcrypt-heavy routes. |
| **Elevation of privilege** | A `[read]` agent delegates itself `[write]` | Server-resolved scope intersection at delegation time — the delegator's own verified JWT, never a client-supplied parameter. |
| **The lethal trifecta** (not in classic STRIDE) | Untrusted content → injected instructions → exfiltration | Provenance-aware OPA policy denies high-risk capabilities in a causal trace that already touched untrusted content (Slice 13) — a heuristic, not a solved problem. |

---

## License

MIT — see the `LICENSE` file.
