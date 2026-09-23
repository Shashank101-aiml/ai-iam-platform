# AI-IAM Platform (Auth0 for Autonomous AI Agents)

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115.0-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Open Policy Agent](https://img.shields.io/badge/OPA-ReBAC%20Policy%20Engine-7B42BC?style=for-the-badge)](https://www.openpolicyagent.org/)
[![Redis](https://img.shields.io/badge/Redis-Revocation%20Index-DC382D?style=for-the-badge&logo=redis&logoColor=white)](https://redis.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

> An identity, credential-lifecycle, ReBAC authorization, and tamper-evident audit control plane for AI agents — hardened across 16 dependency-ordered slices, then made usable as a product (landing page, self-serve trial org, operator dashboard) in slices 17–23. Every slice was verified live against a real Docker stack, not just unit tests.

---

## Status

Every claim below reflects code that exists, is tested, and has been verified against a real running Docker Compose stack — not a design document. If a capability isn't built yet, it's listed under **Honestly not done** instead of implied.

**Done — the control plane (Slices 1–16):**
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
- CI, a dashboard with no mock-data fallback, and honest docs (Slice 16)

**Done — the product on top of it (Slices 17–23):**
- **Frontend overhaul (17):** a marketing landing page, a real login flow against `/auth/login` + `/auth/me`, client-side routing with an auth guard, and the operator dashboard on Tailwind CSS v4 with a mobile drawer navigation.
- **White + red console reskin (18):** the dashboard and login moved off the original dark theme onto one light, single-accent console theme.
- **Self-serve trial org (19):** a visitor can create their own organization and admin account from the landing page — see [Tenant onboarding](#tenant-onboarding-slice-19).
- **Register-agent form (20):** agents can be created, activated, and issued keys entirely from the dashboard; previously creation was API-only.
- **Mock MCP server, bindings form, SSRF host allowlist (21):** the pre-execution MCP proxy can now be exercised live end to end, and a real SSRF gap the trial signup would otherwise have widened is closed.
- **Block reasons (22):** every blocked MCP call is recorded and shown as what it actually was (policy denial, provenance denial, tool filter, missing binding, …) instead of one generic "blocked".
- **Authenticated `/auth/register` (23):** found while writing this README — the route that adds an operator to an org took no authentication, so anyone who knew an org's UUID could add themselves as one of its operators. It now requires an operator of that org (or a superuser), and a cross-tenant attempt looks exactly like a nonexistent org.

**Honestly not done:**
- **No real SPIFFE/SPIRE attestation.** `spiffe_id` is a structured, format-checked identifier string (`spiffe://<trust-domain>/ns/<org>/sa/<agent>`) — there is no SPIRE server, no X.509 cert, no cryptographic workload attestation anywhere in this codebase. The actual cryptographic trust boundary is the RS256 JWT issued at token exchange. See `backend/app/core/spiffe.py`'s module docstring for the full explanation.
- **Trial signup abuse defense is rate limiting only.** There is no email verification, CAPTCHA, terms-of-service step, or trial expiry/cleanup job — a trial org lives forever.
- **No MFA.** Operator sessions are 8-hour bearer tokens (`auth_service.create_access_token`), with no second factor behind them.
- **The MCP proxy speaks a simplified HTTP tool-call protocol, not the MCP JSON-RPC transport.** It forwards `POST {server_url}/tools/{tool_name}` with `{"arguments": {...}}` and expects a JSON `200`. The bundled `mock_mcp/` server matches that and is a demo, not a real MCP server.
- **The MCP host allowlist defaults to the demo hosts.** `MCP_SERVER_URL_ALLOWED_HOSTS` ships as the mock server's hostnames; a real deployment must set it to its own MCP servers.
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
        I -- deny with reasons --> J[Blocked, audited, committed immediately]
        I -- allow --> K[tool_filter check] --> L[External MCP server]
    end

    subgraph Tamper-evident audit
        H -->|hash args/results, never store raw| M[(Postgres audit_logs - INSERT-only role)]
        M -->|periodic + on-demand| N[SHA-256 chain verification]
    end

    subgraph Observability
        G -.->|structured JSON logs, redacted, causal_trace_id| O[stdout]
        H -.->|denials by cause, delegation depth, rotations, verify duration| P[/metrics - Prometheus/]
    end
```

---

## What's actually enforced, by slice

### Tenant onboarding (Slice 19)
- `POST /api/v1/auth/trial-signup` is public and creates a brand-new Organization plus its first admin User in one transaction, then returns a logged-in operator token (same shape as `/auth/login`). Before this, the only ways to get an org + admin were `scripts/bootstrap.py` (needs shell/DB access) or the superuser-only `POST /organizations` (which creates no user at all).
- The new admin is **never a platform superuser**: the endpoint reuses `auth_service.create_user()`, which does not read or set `is_superuser`, so a trial admin only ever sees their own org.
- Rate-limited to 3 requests/minute/IP (`RATE_LIMIT_TRIAL_SIGNUP_PER_MINUTE`) with the same Redis fixed-window limiter that protects `/auth/login` and `/token/exchange`. The organization creation is audited (`organization.created`).
- A trial org starts **empty** — no seeded demo agents, matching `scripts/bootstrap.py`'s "no demo data" stance rather than `scripts/seed_db.py`'s.
- Adding a teammate later is `POST /api/v1/auth/register`, which **requires an authenticated operator**: a regular operator can only add users to their own org, a superuser to any. Naming someone else's org gets the same `404` as a nonexistent one, so the response never confirms an org id is valid. (This route used to take no authentication at all — anyone who knew an org's UUID could add themselves as an operator of it; fixed in Slice 23.)

### Identity and tokens
- RS256 JWTs for agents (asymmetric — public key verifies without a DB round-trip), HS256 for human operators. 15-minute agent access tokens, 10-minute delegation tokens.
- API keys: `aiiam_<64 hex chars>`, bcrypt-hashed, never stored in plaintext. Presented at token exchange as the compound `kid_xxx:aiiam_xxx` (the key ID from issuance, a colon, then the secret) for O(1) lookup — an org-wide bcrypt scan was a real CPU-exhaustion vector before Slice 4. A bare `aiiam_…` is rejected.
- Zero-downtime rotation with a grace window — both the old and new key work during the transition.
- **Task-scoped tokens (Slice 12):** an optional `intent: {mcp_server_id, tool_name}` at `/token/exchange` binds a token to exactly one call. Replaying it against any other tool gets a distinct `token_not_authorized_for_action`, not a generic policy denial. Mandatory for scopes named in `MCP_TASK_SCOPING_REQUIRED_SCOPES` (`credential:rotate` by default).
- **`on_behalf_of` (Slice 11):** every agent token traces back to the human operator who activated it, or to whoever a later, revocable grant vouches for — resolved server-side, never caller-supplied.

### Delegation
- Real chain loading from `DelegationGrant.parent_grant_id`, walked from the database — not a client-trusted depth counter. `MAX_DELEGATION_DEPTH` (default 5) and cycle detection (`A → B → A`) are both enforced against that real chain, and an agent can't delegate to itself.
- Scope attenuation resolved from the delegating agent's own verified JWT, intersected with its current `allowed_scopes` — a delegatee can never end up with a scope the delegator didn't actually hold at delegation time. Requesting one it doesn't hold is a `422`.
- Revoking a grant cascades forward through every descendant grant, blacklisting each one's JTI immediately (Slice 9) — not waiting for natural expiry.

### Policy (OPA / Rego)
- Every tool-execution decision is a real query to a running OPA instance (`backend/policies/authz.rego`), fail-closed on any timeout, connection error, or ambiguous response.
- **Provenance-aware authorization (Slice 13):** `mcp_bindings` can mark a server's results as `untrusted_source` and tag specific tools with risk categories (`external_send`, `credential_access`). If any earlier call in the same `causal_trace_id` pulled untrusted content, a later high-risk call in that trace is denied outright — a heuristic against "read untrusted content → get instructions injected → exfiltrate," not a claim to have solved prompt injection.
- **Deny reasons (Slice 22):** the policy also returns `deny_reasons` (`scope_not_granted`, `blocked_tool`, `delegation_depth_exceeded`, `malformed_input`, `provenance_tainted_high_risk_capability`). It is informational only — `allow` is the single enforcement point, and a policy test asserts a request is allowed exactly when the set is empty. The app uses it to say *why* something was denied.

### MCP proxy
- `mcp_server_url` is resolved server-side from the calling agent's own `mcp_bindings`, never from the request body (closes an SSRF that was live and exploitable before Slice 7).
- **Binding URLs are allowlisted at registration (Slice 21).** A binding's own `server_url` used to be trusted because it was "operator-authored" — an assumption that stopped holding once anyone could become an operator through trial signup. `agent_service.register()` now rejects any binding whose host isn't in `MCP_SERVER_URL_ALLOWED_HOSTS`, plus non-`http(s)` schemes and embedded credentials (`http://mock-mcp@evil.com`), so a visitor can't aim the proxy at `postgres`, `redis`, `opa`, or a cloud metadata address.
- Per-binding `tool_filter` allowlist enforced even when scope/policy would otherwise allow a call.
- Response size cap, per-call timeout, and a per-server circuit breaker bound the blast radius of a slow or malicious downstream MCP server.
- A blocked or errored call's session/audit rows are committed immediately inside the service — not left to a caller whose exception handling would otherwise roll them back.
- **Every block is recorded as what it was (Slice 22).** `policy_decision` is one of `policy_denied`, `provenance_denied`, `policy_unavailable` (OPA unreachable — still denied, failed closed), `tool_filter_denied`, `binding_denied`, `resource_denied`, or `task_scope_denied`, each with a specific reason. The dashboard labels them, the audit entry carries the full text, and `aiiam_mcp_tool_denials_total` groups by the same values.

### Audit log
- Every entry hash-chains to the previous one (`SHA256(previous_hash + action + details + actor_id + trace_id)`); tampering with any historical row breaks every hash after it.
- Writes go through a dedicated Postgres role with INSERT + SELECT only — no UPDATE, no DELETE, enforced by Postgres itself.
- `verify_chain` streams in batches (`yield_per`), so verifying a million-entry chain runs in fixed memory. A periodic background worker replays every org's chain and raises a `CRITICAL` log the moment one is found broken, rather than waiting for someone to call the verify endpoint.

### Standards alignment (MCP OAuth 2.1, Slice 10)
- This platform is its own spec-compliant Authorization Server: `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, `/.well-known/jwks.json`, Dynamic Client Registration (PKCE-only public clients — no client secret is ever issued), RFC 8707 Resource Indicators binding a token to one `mcp_server_id`, RFC 9207 `iss` in the redirect.

### Observability (Slice 14)
- Structured, redacted JSON logs — every line carries `causal_trace_id`; a plaintext API key accidentally logged is masked before it's ever written.
- `/metrics` (Prometheus format): generic HTTP histograms plus domain counters — denials by cause, a delegation-depth histogram, credential rotations, audit-chain verification duration.
- A real liveness/readiness split: `/health` never touches Postgres/OPA (a real orchestrator's liveness probe must not restart a process over a dependency blip); `/health/detailed` does, for readiness.

### Runtime hardening (Slice 15)
- CORS never combines a wildcard origin with credentials (the old config was spec-invalid and silently non-functional in every real browser).
- Redis-backed rate limiting on `/auth/login`, `/token/exchange`, and `/auth/trial-signup` — a shared limit across every worker process, not a per-process counter; fails open on a Redis outage (availability, not correctness, is what a rate limiter protects).
- The credential rotator, ephemeral reaper, and audit verifier each run behind a Postgres advisory lock, so a multi-worker deployment (`--workers 4`) doesn't race itself rotating the same keys.
- Every image pinned by digest; the backend container runs read-only, non-root, with all Linux capabilities dropped (the mock MCP server gets the same treatment).

---

## The operator dashboard

React 18 + Vite + Tailwind CSS v4, served on `:5173`. Routes: `/` (landing), `/login`, `/trial` (self-serve signup), and `/dashboard` (behind an auth guard). The dashboard has four tabs:

| Tab | Shows |
| :--- | :--- |
| **Agent Hierarchy** | Every agent in your org; **Register New Agent** (name, scopes, optional parent, max depth, optional MCP bindings), **Activate SPIFFE ID**, **Issue Zero-Downtime API Key** |
| **Multi-Hop Delegation** | The live delegation tree and the scope-attenuation / depth-ceiling rules |
| **Append-Only Ledger** | The hash-chained audit log, searchable, with per-entry previous/current hashes |
| **Pre-Execution Proxy** | Every MCP call attempt: allowed, or blocked with its cause and reason |

There is **no mock-data fallback**: if the backend is unreachable the dashboard shows an explicit "Backend unreachable" state with a retry — never fabricated agents or audit rows. "Verify Audit Integrity" in the header runs the real chain check.

The Register Agent form's MCP bindings box takes JSON; **Insert demo bindings** fills three bindings against the bundled mock server (a plain data server, an `untrusted_source` web-search server, and a mail server whose `send_email` is tagged `external_send`).

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
├── mock_mcp/                      # demo-only downstream MCP server (stdlib Python)
├── docs/                          # architecture, credential-lifecycle, delegation-chain,
│                                  # threat-model, testing
├── frontend/                      # React/Vite dashboard — no mock data fallback
│   └── src/
│       ├── pages/                 # LandingPage, LoginPage, TrialSignupPage, DashboardPage
│       ├── components/            # dashboard tabs, modals, and landing/ sections
│       └── services/api.js        # the only place the frontend talks to the backend
├── docker/                        # docker-compose.yml, Dockerfile — the actual verified environment
├── .github/workflows/ci.yml       # pytest + opa test + lint/type-check/build + dependency/secret scan
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
This starts Postgres, OPA, Redis, the mock MCP server, and the backend (which runs its own `alembic upgrade head` and seed script on startup), plus the React dashboard. No manual migration step, no manual seeding — `docker compose up` from a clean volume is the tested path.

| Service | Host port | Notes |
| :--- | :--- | :--- |
| Dashboard | `5173` | `/` landing, `/login`, `/trial`, `/dashboard` |
| Backend API | `8000` | Swagger UI at `/docs` only when `DEBUG=true`, as the local-dev compose file sets |
| Mock MCP server | `8090` | `GET /calls` lists what it actually received |
| OPA | `8181` | |
| Redis | `6380` | host mapping only; the backend uses `redis:6379` internally |
| Postgres | `5432` | |

If a default port is already taken on your machine, put the remap in a git-ignored `docker/docker-compose.override.yml` and use the `!override` YAML tag on `ports:` — Compose **appends** list keys across files by default, which would bind both the old and new port.

### 3. Confirm it's healthy
```bash
docker compose -f docker/docker-compose.yml ps
```
All services should report `healthy` (the frontend has no healthcheck).

### 4. Get in
- **Your own org:** open `http://localhost:5173` and click **Start your free trial org** (or `POST /api/v1/auth/trial-signup`). You land in an empty dashboard as the admin of a fresh org.
- **The seeded demo org:** `admin@acmecorp.ai` / `AdminPass123!`. These credentials are created by `scripts/seed_db.py`, which the compose file runs on every start — **local development / demo only**. A real deployment uses `scripts/bootstrap.py` (your own admin email, an auto-generated password, no demo data) and must not run the seed script.

### Changing code while it runs
- **Frontend:** bind-mounted with hot reload — just save.
- **Backend:** built into the image on purpose (no source bind mount, no `--reload`, matching a real deployment), so rebuild: `docker compose -f docker/docker-compose.yml up -d --build backend`.
- **Rego policy:** OPA loads policy only at startup — `docker compose -f docker/docker-compose.yml restart opa` after editing `backend/policies/`.

### Running the test suite
```bash
docker run --rm --network docker_default \
  -v "$(pwd)/backend:/app/backend" \
  -e DATABASE_URL="postgresql+asyncpg://aiiam_user:supersecretpassword@postgres:5432/aiiam_db" \
  -e TEST_DATABASE_URL="postgresql+asyncpg://aiiam_user:supersecretpassword@postgres:5432/aiiam_test_db" \
  -e SCHEMA_CHECK_DATABASE_URL="postgresql+asyncpg://aiiam_user:supersecretpassword@postgres:5432/aiiam_schema_check_db" \
  -e OPA_URL="http://opa:8181" \
  -e REDIS_URL="redis://redis:6379/0" \
  -w /app/backend docker-backend \
  python -m pytest tests/ -q
```
`SCHEMA_CHECK_DATABASE_URL` matters: `test_schema_sync` defaults to `localhost:5432` and fails inside the container without it. As of Slice 23 that is 116 tests; the Rego policy has its own 23:
```bash
docker run --rm -v "$(pwd)/backend/policies:/policies:ro" \
  openpolicyagent/opa:latest-debug@sha256:f37df2fabfe6e3d5f62579b21dbba2c4054738c3e699dac5bf4521b1370494f8 \
  test /policies -v
```
(See `.github/workflows/ci.yml` for the same thing running automatically on every pull request.)

---

## Verify it yourself

Five minutes, no seeded credentials, against your own throwaway org. It signs up, registers two agents (one bound to the mock MCP server), acts as an agent, and checks the claims that matter. Run against a stack from the steps above (`BASE`/`MOCK` default to the standard ports):

```bash
BASE=${BASE:-http://localhost:8000/api/v1}
MOCK=${MOCK:-http://localhost:8090}
J='Content-Type: application/json'
pick() { sed -E "s/.*\"$1\":\"([^\"]+)\".*/\1/"; }

# 1. Your own org + operator (public, rate-limited). Returns a logged-in token.
N=$RANDOM
OP=$(curl -s -X POST $BASE/auth/trial-signup -H "$J" \
  -d "{\"org_name\":\"Try $N\",\"admin_email\":\"try$N@example.com\",\"admin_password\":\"TrialPass123!\"}" | pick access_token)
AUTH="Authorization: Bearer $OP"

# 2. Two agents: "Caller" is bound to the mock MCP server, "Worker" is a delegation target.
BINDINGS='[{"server_id":"data-mcp","server_url":"http://mock-mcp:8080","tool_filter":["query_database"]},
 {"server_id":"web-mcp","server_url":"http://mock-mcp:8080","tool_filter":["search_web"],"untrusted_source":true},
 {"server_id":"mail-mcp","server_url":"http://mock-mcp:8080","tool_filter":["send_email"],"tool_capabilities":{"send_email":["external_send"]}}]'
new_agent() {
  ID=$(curl -s -X POST $BASE/agents -H "$AUTH" -H "$J" \
    -d "{\"name\":\"$1\",\"allowed_scopes\":[\"tool:execute\"],\"mcp_bindings\":$2}" | sed -E 's/^\{"id":"([^"]+)".*/\1/')
  curl -s -o /dev/null -X POST $BASE/agents/$ID/activate -H "$AUTH"; echo $ID
}
CALLER=$(new_agent Caller "$BINDINGS"); WORKER=$(new_agent Worker "[]")

# 3. Act as the Caller: API key -> short-lived RS256 token.
KEY=$(curl -s -X POST $BASE/agents/$CALLER/keys -H "$AUTH" -H "$J" -d '{"scopes":["tool:execute"],"ttl_days":30}')
AT=$(curl -s -X POST $BASE/token/exchange -H "$J" \
  -d "{\"grant_type\":\"api_key\",\"credential\":\"$(echo $KEY | pick key_id):$(echo $KEY | pick plaintext_key)\"}" | pick access_token)
AGENT="Authorization: Bearer $AT"

echo "--- delegation: try to hand out a scope the Caller does not hold (expect 422)"
curl -s -w '  -> HTTP %{http_code}\n' -X POST $BASE/token/delegate -H "$AGENT" -H "$J" \
  -d "{\"delegatee_agent_id\":\"$WORKER\",\"requested_scopes\":[\"agent:delegate\"]}"

echo "--- MCP proxy (expect 200, 403, 200, 200, 403)"
call() { curl -s -o /dev/null -w "  $1 @ $2 -> HTTP %{http_code}\n" -X POST $BASE/mcp/tools/$1 -H "$AGENT" -H "$J" \
  -d "{\"mcp_server_id\":\"$2\",\"arguments\":{\"q\":\"x\"},\"causal_trace_id\":\"$3-$N\"}"; }
call query_database  data-mcp  allowed   # allowed
call delete_database data-mcp  opa       # always-blocked tool
call send_email      mail-mcp  clean     # high-risk, but nothing untrusted read yet
call search_web      web-mcp   taint     # untrusted read...
call send_email      mail-mcp  taint     # ...then the same trace tries to send: denied

echo "--- did the blocked calls reach the downstream server? (expect 0)"
curl -s $MOCK/calls | grep -c delete_database

echo "--- revocation: a delegation token stops working immediately"
G=$(curl -s -X POST $BASE/token/delegate -H "$AGENT" -H "$J" \
  -d "{\"delegatee_agent_id\":\"$WORKER\",\"requested_scopes\":[\"tool:execute\"]}")
DT=$(echo $G | pick delegation_token); GID=$(echo $G | sed -E 's/.*"grant":\{"id":"([^"]+)".*/\1/')
probe() { curl -s -w "  -> HTTP %{http_code}\n" -X POST $BASE/mcp/tools/probe -H "Authorization: Bearer $DT" -H "$J" -d '{"mcp_server_id":"probe"}'; }
probe                                                                   # authenticated, then blocked (no binding): 403
curl -s -o /dev/null -X POST $BASE/token/delegations/$GID/revoke -H "$AUTH" -H "$J" -d '{"reason":"demo"}'
probe                                                                   # rejected at authentication: 401 token_revoked

echo "--- tamper-evident audit chain"
curl -s $BASE/audit/verify -H "$AUTH"; echo
```

What you should see: the escalation is a `422`; the proxy answers `200/403/200/200/403`; the mock server has **never** received `delete_database` (blocked calls die before execution, not after); the same delegation token goes from `403` (authenticated, then blocked for having no binding) to `401 token_revoked` the moment its grant is revoked; and `chain_valid` is `true`. Then open the dashboard's **Pre-Execution Proxy** tab to see each block labelled with its cause.

Two more checks worth doing by hand: stop the `opa` container and repeat a tool call (it must be denied, recorded as `policy_unavailable` — never allowed by default), and stop the `backend` container and reload the dashboard (an explicit "Backend unreachable" state, not empty tables).

---

## API surface (selected)

| Method | Route | Description | Auth |
| :--- | :--- | :--- | :---: |
| `POST` | `/api/v1/auth/trial-signup` | Create your own org + first admin, returns a logged-in token | ❌ (rate-limited) |
| `POST` | `/api/v1/auth/login` | Operator login → HS256 JWT | ❌ (rate-limited) |
| `GET` | `/api/v1/auth/me` | The logged-in operator | Operator JWT |
| `POST` | `/api/v1/auth/register` | Add an operator to an org (your own; any org for superusers) | Operator JWT |
| `POST` | `/api/v1/organizations` | Create a further tenant | Superuser JWT |
| `GET` / `POST` | `/api/v1/agents` | List / register an agent identity (`PENDING`); `mcp_bindings` host-allowlisted | Operator JWT |
| `POST` | `/api/v1/agents/{id}/activate` | Assign SPIFFE-style identifier, move to `ACTIVE` | Operator JWT |
| `POST` | `/api/v1/agents/{id}/keys` | Issue a hashed API key (shown once) | Operator JWT |
| `POST` | `/api/v1/agents/{id}/on-behalf-of-grants` | Vouch for a human's authority behind an agent's tokens | Operator JWT |
| `POST` | `/api/v1/token/exchange` | `kid_…:aiiam_…` → RS256 access token (optional task-scoping `intent`) | API key (rate-limited) |
| `POST` | `/api/v1/token/delegate` | Multi-hop delegation with real scope attenuation | Agent bearer |
| `POST` | `/api/v1/token/delegations/{id}/revoke` | Revoke a grant — cascades to every descendant | Operator JWT |
| `POST` | `/api/v1/token/inspect` | Verify a token's signature and decode its claims | ❌ |
| `POST` | `/api/v1/mcp/tools/{tool_name}` | Pre-execution ReBAC + provenance-aware proxy | Agent bearer |
| `GET` | `/api/v1/mcp/sessions` | Every proxied call, with its `policy_decision` and reason | Operator JWT |
| `GET` | `/api/v1/audit/logs` / `/api/v1/audit/verify` | The audit log / recompute and verify the SHA-256 hash chain | Operator JWT |
| `POST` | `/api/v1/oauth/register` | Dynamic Client Registration (RFC 7591) | Operator JWT |
| `GET` | `/api/v1/oauth/authorize` → `POST /api/v1/oauth/token` | Authorization Code + PKCE (RFC 8707 resource binding) | Operator JWT / PKCE |
| `GET` | `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, `/.well-known/jwks.json` | OAuth/MCP discovery | ❌ |
| `GET` | `/health` / `/health/detailed` | Liveness / readiness | ❌ |
| `GET` | `/metrics` | Prometheus exposition | ❌ |

---

## Configuring a real deployment

Everything below is read from environment variables (`backend/app/core/config.py`); the compose file's local-dev values are not production values.

| Setting | Why it matters |
| :--- | :--- |
| `JWT_SECRET_KEY`, `DB_PASSWORD`, `AUDIT_DB_PASSWORD` | Must come from a real secrets backend. The app refuses to boot on the known default JWT secret outside `DEBUG` mode. |
| `MCP_SERVER_URL_ALLOWED_HOSTS` | JSON list of the MCP server hostnames agents may be bound to, e.g. `'["mcp.internal.example.com"]'`. **Defaults to the mock server's hostnames**, so agent registration rejects everything else until you set it. |
| `CORS_ALLOWED_ORIGINS` | An explicit origin list — never `*` together with credentials. |
| `RATE_LIMIT_LOGIN_PER_MINUTE`, `RATE_LIMIT_TOKEN_EXCHANGE_PER_MINUTE`, `RATE_LIMIT_TRIAL_SIGNUP_PER_MINUTE` | Per-IP limits (defaults 10 / 60 / 3). Consider disabling public trial signup entirely outside a demo. |
| `MAX_DELEGATION_DEPTH` | The application ceiling; `authz.rego` deliberately duplicates it as an independent second check, so change both. |

---

## Security design (STRIDE, as it actually stands)

| Threat | Attack vector | Defense actually implemented |
| :--- | :--- | :--- |
| **Spoofing** | Forged agent identity | RS256-signed, short-lived JWTs verified on every request. **Not** X.509/SPIRE attestation — see Status above. |
| **Tampering** | Rewriting audit history to hide an action | Append-only SHA-256 hash chain + a Postgres role with no UPDATE/DELETE privilege on `audit_logs`. |
| **Repudiation** | An agent denies having executed a destructive call | Every MCP call's `args_hash`/`result_hash` links to the signed JWT's `causal_trace_id` in an append-only log; blocked calls are recorded with their cause. |
| **Information disclosure** | A DB dump leaks credentials | API keys bcrypt-hashed (never stored plaintext); MCP tool args/results stored only as SHA-256 hashes, never raw. |
| **Denial of service** | Runaway delegation, a wedged downstream MCP server, mass tenant creation | Hard `MAX_DELEGATION_DEPTH`; per-server circuit breaker + response-size cap + timeout on the MCP proxy; Redis-backed rate limiting on unauthenticated bcrypt-heavy routes, including trial signup. |
| **Elevation of privilege** | A `[read]` agent delegates itself `[write]`; a trial admin reaching other tenants | Server-resolved scope intersection at delegation time — the delegator's own verified JWT, never a client-supplied parameter. Self-serve admins are never superusers, so they only ever see their own org. |
| **Server-side request forgery** | An operator (including any trial-org admin) binds an agent to an internal address so the proxy calls it | The proxy resolves the URL from the agent's bindings, never the request; bindings are host-allowlisted at registration (`MCP_SERVER_URL_ALLOWED_HOSTS`), scheme- and userinfo-checked. |
| **The lethal trifecta** (not in classic STRIDE) | Untrusted content → injected instructions → exfiltration | Provenance-aware OPA policy denies high-risk capabilities in a causal trace that already touched untrusted content (Slice 13) — a heuristic, not a solved problem. |

---

## License

MIT — see the `LICENSE` file.
