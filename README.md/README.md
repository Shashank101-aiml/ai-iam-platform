# AI-IAM Platform (Auth0 for Autonomous AI Agents)

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115.0-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16+-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![SPIFFE / SPIRE](https://img.shields.io/badge/SPIFFE%20%2F%20SPIRE-Workload%20Identity-E05D44?style=for-the-badge)](https://spiffe.io/)
[![Open Policy Agent](https://img.shields.io/badge/OPA-ReBAC%20Policy%20Engine-7B42BC?style=for-the-badge)](https://www.openpolicyagent.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

> **Enterprise-grade Identity, Credential Lifecycle, Relationship-Based Access Control (ReBAC), and Tamper-Evident Audit Governance built specifically for multi-agent autonomous ecosystems.**

---

## 🌟 The Vision & Core Problem

In modern multi-agent systems (e.g., **LangGraph**, **CrewAI**, **AutoGen**, and **Model Context Protocol / MCP** server ecosystems), AI agents operate autonomously—executing powerful tools, accessing sensitive databases, and delegating complex sub-tasks to specialized peer agents.

### Why Traditional IAM Fails for AI Agents:
1. **Static Human Secrets (`API Keys in Env Vars`)**: Developers typically hardcode long-lived human API keys (`OPENAI_API_KEY`, `DB_PASSWORD`) directly into agent workflows. If an agent prompt-injects or malfunctions, the blast radius is total.
2. **Uncontrolled Delegation & Privilege Escalation**: When **Orchestrator Agent A** (holding `[read, write, execute]`) delegates research to **Sub-Agent B**, Agent B often inherits or assumes full access, leading to runaway multi-hop chain exploits.
3. **Reactive vs. Proactive Tool Governance**: Most observability platforms log tool executions *after the fact*. If an agent calls `delete_database` or `exfiltrate_pii` via an MCP tool, logging it post-execution is catastrophic—it must be cryptographically verified and **blocked pre-execution**.
4. **Lack of Causal Audit Accountability**: When an autonomous chain of 5 agents makes a critical decision, determining **which agent, token, or delegation link caused what** is nearly impossible without strict causal graph tracking and tamper-evident append-only logs.

---

## 🏛️ Architecture & System Overview

The **AI-IAM Platform** treats AI agents as first-class cryptographic workload identities (`SPIFFE SVIDs`). It acts as the central governance control plane between autonomous AI agents and their target tools/APIs.

```mermaid
graph TD
    subgraph Identity & Authentication
        A[Orchestrator Agent] -->|1. Request Token + Causal Trace| B(AI-IAM Auth Router / RS256 JWT)
        B -->|2. Verify Workload ID| C[SPIFFE / SPIRE Workload Socket]
    end

    subgraph Delegation Chain Governance
        A -->|3. Delegate Scopes: Scope Attenuation Check| D[Sub-Agent / Delegatee]
        D -->|4. Present Delegation JWT + jti| E[AgentAuthMiddleware]
    end

    subgraph Active Policy & MCP Tool Proxy
        E -->|5. Tool Call Execution Request| F[MCP Proxy Service / API]
        F -->|6. Pre-Execution ReBAC Evaluation| G[Open Policy Agent - OPA Rego Engine]
        G -- Deny Fail-Closed --> H[Blocked & Logged Pre-Execution]
        G -- Allow --> I[External MCP Server / Tool Execution]
    end

    subgraph Tamper-Evident Causal Audit Engine
        F -->|7. Hash(Args/Results) + Trace ID| J[(Postgres Append-Only Audit Log)]
        J -->|8. SHA256 Chain Verification| K[Tamper-Evident Hash Chain Sequence]
    end
```

---

## ✨ Key Enterprise Capabilities

### 1. 🔐 Cryptographic Workload Identity (`SPIFFE/SPIRE`) & RS256 JWTs
* **X.509 SVID Workload Attestation**: Assigns canonical `spiffe://<trust-domain>/org/<org_id>/agent/<agent_id>` identities to verified agent runtimes.
* **Short-Lived Asymmetric Tokens**: Issues asymmetric **RS256 JWTs** with deliberately short lifetimes (`15 minutes` for access tokens, `10 minutes` for delegation grants). Public verification keys (`public.pem`) allow distributed microservices to verify agent identity locally without DB bottlenecks.
* **Just-In-Time (`JIT`) Ephemeral Activation**: Ephemeral agents spawned for single-run background workflows get activated JIT (`jit_activate`) with a hard-stop task TTL, automatically transitioning to `DECOMMISSIONED` status upon expiration.

### 2. 🔗 Multi-Hop Delegation Chains with Zero Privilege Escalation
* **Mathematical Scope Attenuation**: Enforces strict scope intersection (`validate_scope_subset`). If an agent holds `[read, execute]`, attempting to delegate `[write]` immediately throws a cryptographic rejection (`PermissionDeniedError`).
* **Runaway Chain Protection**: Enforces a hard **Maximum Delegation Depth** (`MAX_DELEGATION_DEPTH = 5`) and mathematical cycle detection (`Agent A → Agent B → Agent A` is rejected immediately).
* **Auditable Delegation Links (`DelegationGrant`)**: Every link in the chain is assigned a unique JWT ID (`jti`) and tracked in the database, allowing instant real-time revocation of a parent grant that immediately invalidates all downstream hops.

### 3. 🛡️ Relationship-Based Access Control (`ReBAC` via Open Policy Agent)
* **Decoupled Policy as Code**: Evaluates access decisions (`check_permission`) by querying an external **Open Policy Agent (`OPA`)** server using version-controlled `.rego` policies (`v1/data/aiiam/authz`).
* **Granular Context Evaluation**: Sends the full agent identity graph—including `agent_id`, `org_id`, `action`, `resource.type`, `resource.id`, `token_scopes`, and `delegation_depth`—to determine exact access rights.
* **Fail-Closed Guarantee**: Any network timeout, OPA connection error, or ambiguous policy evaluation defaults strictly to **DENY** (`HTTP 403 Forbidden`).

### 4. ⚡ Active Pre-Execution Policy Proxying (`MCP Proxy Service`)
* **Interception Pre-Execution**: Acts as an intelligent reverse proxy (`/api/v1/mcp/...`) for the **Model Context Protocol (MCP)**. Before any tool call (`tool:execute`) reaches the external tool provider, the proxy evaluates the ReBAC rules.
* **Privacy-Preserving Content Hashes**: Never stores raw tool arguments (`tool_args`) or execution responses in database rows to prevent leaking API keys, passwords, or PII. Instead, computes `args_hash = SHA256(JSON(args))` and `result_hash = SHA256(JSON(result))` alongside non-sensitive structural metadata (`McpSession`).

### 5. 📜 Tamper-Evident Causal Hash Chain Audit Trail
* **Append-Only Database Design**: Designed for zero update/delete access at the PostgreSQL role level (`INSERT-only`).
* **Cryptographic Hash Chaining**: Every log entry computes:
  $$\text{entry\_hash} = \text{SHA256}(\text{previous\_hash} + ":" + \text{action} + ":" + \text{details\_json} + ":" + \text{actor\_id} + ":" + \text{causal\_trace\_id})$$
  Starting from a 64-zero genesis hash (`AUDIT_CHAIN_GENESIS`), any unauthorized mutation of historical records breaks the sequence and is caught instantly during integrity verification.
* **Causal Tree Reconstruction**: Every token issuance, delegation link, and MCP tool call shares a unified `causal_trace_id` and `parent_event_id`, enabling complete graphical reconstruction of causal dependency chains.

### 6. 🔄 Zero-Downtime Credential Rotation & PKCE
* **Proactive Rotation with Grace Windows**: When an API key is rotated (`rotate_key`), a new key (`aiiam_<new_hex>`) is issued while the previous bcrypt hash (`previous_hashed_secret`) remains active inside a configurable grace period (default `1 hour`). Both keys work during deployment transitions without breaking production agents.
* **Zero Plaintext Storage**: API keys (`aiiam_<32_random_hex_bytes>`) are shown once upon issuance. Only salted `bcrypt` hashes (`BCRYPT_ROUNDS = 12`) are persisted. Safe identifiers (`key_id = kid_...`) and hints (`key_hint = ...f4e2`) ensure secure logging.
* **Proof Key for Code Exchange (`PKCE`)**: Built-in support for `code_verifier` and `code_challenge` (`SHA256` digest verification) to secure agent-to-agent authorization code flows against interception attacks.

---

## 🗂️ Project Hierarchy & Module Walkthrough

```text
ai-iam-platform/
├── README.md/                   # Project documentation directory & overview
│   └── README.md                # Main technical specification & vision guide
├── backend/                     # FastAPI Async Backend Application
│   ├── app/
│   │   ├── api/                 # REST Router Handlers (/api/v1)
│   │   │   ├── agents.py        # Agent registration, provisioning, JIT activation & status
│   │   │   ├── api_keys.py      # Zero-downtime key issuance, rotation & revocation
│   │   │   ├── audit_logs.py    # Tamper-evident hash chain query & verification endpoints
│   │   │   ├── auth.py          # Operator & Agent authentication routes
│   │   │   ├── health.py        # Lifespan healthchecks & OPA/DB connectivity status
│   │   │   ├── mcp_proxy.py     # Pre-execution ReBAC tool interception proxy
│   │   │   ├── organizations.py # Tenant & organization governance
│   │   │   ├── roles.py         # Role definitions & scope mappings
│   │   │   ├── token.py         # RS256 JWT access & delegation token exchange
│   │   │   └── users.py         # Human operator management
│   │   ├── core/                # Core Cryptographic & Policy Primitives
│   │   │   ├── config.py        # Pydantic BaseSettings (DB, OPA, SPIFFE, JWT configuration)
│   │   │   ├── constants.py     # Enums: AgentStatus, AuditAction, TokenType, PermissionScope
│   │   │   ├── delegation.py    # Multi-hop delegation validator, cycle detection & attenuation
│   │   │   ├── jwt.py           # RS256 encode/decode, jti extraction, expiration tracking
│   │   │   ├── permissions.py   # ReBAC HTTP client to Open Policy Agent (OPA)
│   │   │   ├── security.py      # Bcrypt hashing, API key generator, PKCE challenge pairs
│   │   │   └── spiffe.py        # SPIFFE SVID parser & SPIRE Unix domain socket client
│   │   ├── db/                  # Database Session & Async Engine
│   │   │   ├── base.py          # Base declarative class & UUID/Timestamp mixins
│   │   │   └── session.py       # Async SQLAlchemy engine & session pool configuration
│   │   ├── middleware/          # Outer/Inner HTTP Request Middleware Stack
│   │   │   ├── agent_auth.py    # Agent JWT bearer extraction, jti check & RS256 verification
│   │   │   └── trace_propagation.py # Distributed causal trace ID injection (X-Trace-ID)
│   │   ├── models/              # SQLAlchemy 2.0 Async ORM Models
│   │   │   ├── __init__.py      # Model registry for Alembic discovery
│   │   │   ├── agent.py         # Agent identities, SPIFFE IDs, hierarchy & MCP bindings
│   │   │   ├── api_key.py       # Bcrypt hashes, kid_ tracking, grace rotation windows
│   │   │   ├── audit_log.py     # Append-only causal hash chain table with sequence numbers
│   │   │   ├── base.py          # TimestampMixin (created_at, updated_at) & UUID generators
│   │   │   ├── delegation_grant.py # Active/revoked agent-to-agent delegation records
│   │   │   ├── mcp_session.py   # MCP proxy execution history with privacy SHA256 hashes
│   │   │   ├── organization.py  # Multi-tenant organization boundaries
│   │   │   ├── permission.py    # Granular permission scope definitions
│   │   │   ├── role.py          # Role descriptions & agent_roles many-to-many tables
│   │   │   └── user.py          # Human operator credentials & superuser flags
│   │   ├── repositories/        # Async Database Access Layer (Repository Pattern)
│   │   │   ├── agent_repo.py    # CRUD and SPIFFE ID assignment queries
│   │   │   ├── api_key_repo.py  # Active key scanning, usage tracking & rotation transactions
│   │   │   ├── audit_repo.py    # Atomic append-only hash chain computation & insertion
│   │   │   ├── mcp_session_repo.py # MCP session logging & outcome recording
│   │   │   ├── organization_repo.py # Tenant queries
│   │   │   └── user_repo.py     # Operator account queries
│   │   ├── schemas/             # Pydantic v2 Request/Response DTOs
│   │   ├── services/            # Core Business & Security Logic Orchestration
│   │   │   ├── agent_service.py # 2-phase registration/activation, JIT & decommissioning
│   │   │   ├── api_key_service.py # Key verification scan, rotation window & revocation
│   │   │   ├── audit_service.py # Chain verification engine & tamper detection
│   │   │   ├── auth_service.py  # Operator login & token issuance
│   │   │   ├── delegation_service.py # Delegation link creation, attenuation & revocation
│   │   │   ├── mcp_proxy_service.py  # Tool interception, OPA check & HTTP forwarding
│   │   │   ├── organization_Service.py # Organization setup
│   │   │   └── role_service.py  # Role assignment
│   │   ├── utils/               # Shared utilities & helpers
│   │   └── worker/              # Background Async Tasks & Cron Workers
│   │       └── credential_rotator.py # Automated periodic TTL check & grace period cleanup
│   ├── alembic/                 # Alembic Database Migration Scripts
│   ├── main.py                  # FastAPI entry point, lifespan configuration & router wiring
│   └── requirements.txt         # Backend dependencies (fastapi, sqlalchemy, jose, bcrypt, httpx)
├── docs/                        # Architecture & Threat Model Documentation
│   ├── architecture.md          # System architecture specifications
│   ├── credential-lifecycle.md  # Detailed credential rotation & grace state machine
│   ├── delegation-chain.md      # Multi-hop trust math & scope attenuation models
│   └── threat-model.md          # STRIDE analysis against AI agent attack vectors
├── frontend/                    # React / Vite Dashboard & Agent Monitoring UI
│   ├── public/                  # Static assets
│   ├── src/                     # Frontend source code (Components, Pages, Hooks, Services)
│   └── package.json             # Frontend dependency manifest
├── docker/                      # Containerization & Orchestration Configurations
└── scripts/                     # Automation, setup, and key generation scripts
```

---

## 💾 Core Database Schema & Relationships

```mermaid
erDiagram
    ORGANIZATION ||--o{ AGENT : owns
    ORGANIZATION ||--o{ USER : manages
    ORGANIZATION ||--o{ AUDIT_LOG : scopes
    AGENT ||--o{ API_KEY : authenticated_by
    AGENT ||--o{ AGENT : delegates_to_parent
    AGENT ||--o{ DELEGATION_GRANT : grants_or_receives
    AGENT ||--o{ AUDIT_LOG : generates
    AGENT ||--o{ MCP_SESSION : executes_tools
    AUDIT_LOG ||--o| AUDIT_LOG : causal_parent_event
    AUDIT_LOG ||--o| MCP_SESSION : tracks_tool_call

    AGENT {
        string id PK
        string org_id FK
        string name
        string status "PENDING | ACTIVE | SUSPENDED | DECOMMISSIONED"
        string spiffe_id "spiffe://ai-iam.example.com/..."
        string parent_agent_id FK
        int max_delegation_depth
        boolean is_ephemeral
        datetime decommission_at
        string[] allowed_scopes
        jsonb mcp_bindings
    }

    API_KEY {
        string id PK
        string agent_id FK
        string org_id FK
        string key_id "kid_..."
        string hashed_secret "bcrypt hash"
        string key_hint "...f4e2"
        string[] scopes
        boolean is_active
        datetime expires_at
        string rotated_from_id FK
        string previous_hashed_secret "Grace rotation hash"
        datetime previous_key_expires_at
    }

    DELEGATION_GRANT {
        string id PK
        string org_id FK
        string delegating_agent_id FK
        string delegatee_agent_id FK
        string[] scopes
        int delegation_depth
        string delegation_jti
        boolean is_active
        datetime expires_at
        string causal_trace_id
    }

    MCP_SESSION {
        string id PK
        string org_id FK
        string agent_id FK
        string mcp_server_id
        string tool_name
        string args_hash "SHA256(args)"
        string result_hash "SHA256(result)"
        string status "success | error | blocked"
        string policy_decision "allowed | blocked"
        string causal_trace_id
    }

    AUDIT_LOG {
        string id PK
        string org_id FK
        string agent_id FK
        string action "AuditAction Enum"
        jsonb details
        string actor_type "agent | user | system"
        string actor_id
        string causal_trace_id
        string parent_event_id FK
        string entry_hash "SHA256(prev_hash + content)"
        string previous_hash
        int sequence_number
    }
```

---

## 🚀 Getting Started & Local Development Setup

### Prerequisites
* **Python 3.12+**
* **PostgreSQL 16+** (Running locally or via Docker)
* **Open Policy Agent (OPA)** (Optional for local dev, required for ReBAC enforcement)
* **Node.js 20+** (For Frontend dashboard development)

### Step 1: Clone & Configure Environment
```bash
# Clone the repository
git clone https://github.com/LordCenk/agent-iam.git
cd agent-iam

# Create python virtual environment
python -m venv venv
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1
# On macOS/Linux:
source venv/bin/activate

# Install backend dependencies
pip install -r backend/requirements.txt
```

Create a `.env` file in the root directory:
```env
# Application Configuration
APP_NAME="AI-IAM Platform"
APP_VERSION="1.0.0"
DEBUG=True
ENVIRONMENT="development"

# PostgreSQL Database Connection
DATABASE_URL="postgresql+asyncpg://postgres:password@localhost:5432/ai_iam_db"
DATABASE_POOL_SIZE=10

# RS256 Asymmetric Keys (Must generate before starting)
JWT_SECRET_KEY="super-secret-dev-key"
JWT_ALGORITHM="RS256"
JWT_PRIVATE_KEY_PATH="backend/keys/private.pem"
JWT_PUBLIC_KEY_PATH="backend/keys/public.pem"

# TTL Configuration
AGENT_ACCESS_TOKEN_EXPIRE_MINUTES=15
AGENT_REFRESH_TOKEN_EXPIRE_HOURS=2
API_KEY_DEFAULT_TTL_DAYS=30
MAX_DELEGATION_DEPTH=5

# Policy & Identity Engines
SPIFFE_TRUST_DOMAIN="ai-iam.example.com"
SPIRE_AGENT_SOCKET=None  # Set to None for mock dev mode
OPA_URL="http://localhost:8181"
OPA_POLICY_PATH="v1/data/aiiam/authz"
```

### Step 2: Generate Asymmetric RS256 Key Pair
The backend requires RS256 RSA keys to sign and verify short-lived agent tokens:
```bash
mkdir -p backend/keys
# Generate 2048-bit private key
openssl genrsa -out backend/keys/private.pem 2048
# Extract public key for token verification
openssl rsa -in backend/keys/private.pem -outform PEM -pubout -out backend/keys/public.pem
```

### Step 3: Initialize Database Migrations
Create the database in PostgreSQL (`createdb ai_iam_db`), then run Alembic migrations to build the tables:
```bash
cd backend
alembic upgrade head
```

### Step 4: Launch the FastAPI Backend Server
```bash
# From within the backend directory or project root
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
Once started, open the interactive Swagger API documentation at:
👉 **[http://localhost:8000/docs](http://localhost:8000/docs)**

---

## 🔑 Core API Endpoints Reference

| HTTP Method | Route Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :---: |
| `POST` | `/api/v1/organizations` | Bootstrap and register a new multi-tenant organization | ❌ |
| `POST` | `/api/v1/auth/login` | Human operator OAuth login & JWT session issuance | ❌ |
| `POST` | `/api/v1/agents` | **Phase 1 Register**: Create agent identity in `PENDING` status | Operator JWT |
| `POST` | `/api/v1/agents/{id}/activate` | **Phase 2 Activate**: Provision SPIFFE SVID & move to `ACTIVE` | Operator JWT |
| `POST` | `/api/v1/agents/{id}/jit-activate` | **JIT Activate**: Spawns ephemeral agent with hard task TTL | System / Token |
| `POST` | `/api/v1/keys` | Issue new hashed API Key (`aiiam_...`) with safe `kid_` hint | Operator JWT |
| `POST` | `/api/v1/keys/{kid}/rotate` | Proactive **Zero-Downtime Rotation** with grace period | Operator JWT |
| `POST` | `/api/v1/token/exchange` | Exchange API key or SPIFFE SVID for short-lived RS256 JWT | API Key / SVID |
| `POST` | `/api/v1/token/delegate` | Issue multi-hop **Delegation Token** (`Scope Attenuation`) | Agent Bearer |
| `POST` | `/api/v1/mcp/tools/{tool_name}` | **MCP ReBAC Proxy**: Enforce policy & forward tool call | Agent Bearer |
| `GET` | `/api/v1/audit/verify` | Recompute & verify the SHA256 append-only audit hash chain | Operator JWT |

---

## 🔒 Security Design & Threat Mitigation (STRIDE)

| STRIDE Threat | Potential Agent Attack Vector | AI-IAM Architectural Defense |
| :--- | :--- | :--- |
| **Spoofing** | Forged agent identity claiming to be the Orchestrator. | **SPIFFE / SPIRE Workload Attestation**: Workloads must present cryptographically signed X.509 SVID certs bound to their exact Unix domain socket and trust domain. |
| **Tampering** | Malicious insider or compromised agent modifying past audit logs to hide unauthorized tool calls. | **Append-Only SHA256 Hash Chain**: Every `AuditLog` entry hashes its own content plus `previous_hash`. Tampering with row $N$ breaks all subsequent sequence hashes (`sequence_number`). |
| **Repudiation** | Agent denies executing a destructive database drop command via an MCP tool. | **Causal Trace Linkage & Hash Recording**: Every MCP execution (`McpSession`) records `args_hash = SHA256(args)` and links directly to the `causal_trace_id` of the signed agent JWT. |
| **Information Disclosure** | Database dump leaks plaintext API keys or sensitive tool arguments. | **Zero Plaintext Storage**: API keys are hashed with `bcrypt` (`BCRYPT_ROUNDS = 12`). MCP tool arguments/results are stored strictly as `SHA256` content hashes (`_hash_payload`). |
| **Denial of Service** | Runaway recursive agent loop triggering millions of downstream sub-agents or slow MCP tool calls. | **Max Delegation Depth & Duration Tracking**: Hard ceiling `MAX_DELEGATION_DEPTH = 5` blocks infinite chain loops. `McpSession` tracks `duration_ms` to catch and isolate slow/hanging tool calls. |
| **Elevation of Privilege** | Sub-agent delegated with `[read]` attempts to execute `[write]` or `[tool:execute]`. | **Mathematical Scope Attenuation**: Delegation validator (`validate_scope_subset`) guarantees that $\text{Delegated Scopes} \subseteq \text{Delegator Scopes}$. Any escalation attempt is blocked and audited. |

---

## 🗺️ Vision & Future Roadmap

As autonomous AI agents evolve from isolated prompt loops into enterprise-critical multi-agent distributed systems, **AI-IAM Platform** is positioned to become the foundational identity and security layer:

* **Phase 1: Foundation & Core Primitives (Completed)**
  * [x] Async FastAPI backend architecture with SQLAlchemy 2.0 (`asyncpg`)
  * [x] SPIFFE / SPIRE workload SVID URI generation and parsing (`AgentSVID`)
  * [x] RS256 short-lived JWT issuance (`sub: agent:<id>`, `jti` tracking)
  * [x] Zero-downtime API key rotation with grace window state machines (`ApiKeyService`)
  * [x] Multi-hop delegation chains with scope attenuation and cycle detection (`DelegationValidator`)
  * [x] ReBAC Open Policy Agent (`OPA`) HTTP client integration (`Permissions`)
  * [x] Active MCP tool interception reverse proxy with privacy content hashing (`McpProxyService`)
  * [x] Tamper-evident SHA256 append-only causal audit log engine (`AuditLog`)

* **Phase 2: High-Availability Caching & Distributed Enforcement (Next Horizon)**
  * [ ] **Redis Revocation Index**: Real-time `jti` blacklist cache lookup inside `AgentAuthMiddleware` for instantaneous global token revocation (`_check_jti_revoked`).
  * [ ] **Live SPIRE Sidecar Integration**: Full `pyspiffe` X.509 certificate chain validation and automatic SVID rotation listening over `/tmp/spire-agent/public/api.sock`.
  * [ ] **Advanced OPA Rego Bundle Management**: Dynamic hot-reloading of OPA `.rego` policies directly from git repositories (`GitOps` policy pipelines).

* **Phase 3: Full-Stack Observability & Dashboard UI**
  * [ ] **Dark-Mode Glassmorphism React Dashboard**: Populating the `frontend/` directory with a real-time visualization of active agent hierarchies, live delegation chains (`Proof of Trust`), and instant audit log verification graphs.
  * [ ] **Interactive Causal Tree Explorer**: Visualizing multi-hop agent causal traces (`causal_trace_id`) to inspect exactly how an initial orchestrator prompt cascaded into sub-agent delegations and MCP tool executions.

---

## 🤝 Contributing

We welcome contributions from security researchers, AI engineers, and distributed systems developers!

1. Fork the repository (`https://github.com/LordCenk/agent-iam.git`)
2. Create your feature branch (`git checkout -b feature/amazing-agent-guard`)
3. Ensure all tests pass (`pytest backend/tests/ -v`)
4. Commit your changes (`git commit -m 'feat: add ReBAC policy override flag'`)
5. Push to the branch (`git push origin feature/amazing-agent-guard`)
6. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** — see the `LICENSE` file for details. Built with ❤️ for the future of secure, autonomous AI agent ecosystems.
