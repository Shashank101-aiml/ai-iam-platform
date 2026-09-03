# AI-IAM Platform Threat Model & Security Mitigations

This document outlines the security architecture and defensive controls implemented across the AI-IAM Platform to mitigate attacks targeting autonomous AI agent systems.

---

## 1. Threat Matrix & Mitigations

| Threat ID | Attack Vector | System Impact | Architectural Mitigation |
| :--- | :--- | :--- | :--- |
| **TR-001** | **Database Dump / Credential Exfiltration** | Attackers obtain API secrets from stolen database tables. | **Zero-Plaintext Storage**: All API keys are stored as one-way `bcrypt` hashes (`ApiKey.hashed_secret`). Plaintext keys are displayed exactly once during creation or rotation. |
| **TR-002** | **Privilege Escalation via Sub-Agent Delegation** | A low-privilege sub-agent grants itself high-privilege scopes (`threat:mitigate`). | **Mathematical Scope Attenuation**: `DelegationService.delegate` strictly verifies $\text{Scopes}_{\text{child}} \subseteq \text{Scopes}_{\text{parent}}$. Exceeding scopes triggers `HTTP 422`. |
| **TR-003** | **Runaway Multi-Agent Escalation Loops** | Sub-agents spawn recursive child agents until system resources are exhausted. | **Hard Delegation Depth Ceiling**: Every agent hierarchy enforces `MAX_DELEGATION_DEPTH` (default 5). |
| **TR-004** | **Audit Log Tampering / SQL Injection on Logs** | Malicious actors modify historical audit records to hide unauthorized actions. | **Append-Only SHA256 Causal Hash Chain**: Each log entry computes `SHA256(content + previous_hash)`. Any row modification breaks the cryptographic sequence (`broken_at_sequence`). |
| **TR-005** | **Pre-Execution MCP Tool Abuse** | Agents invoke destructive tools (`drop_table`, `delete_cloud_bucket`) directly. | **Pre-Execution ReBAC Proxy**: All tool requests must pass through `/api/v1/mcp/tools/{tool_name}`. The proxy checks OPA ReBAC policies *before* forwarding HTTP requests. |
| **TR-006** | **Argument / Result Privacy Leakage** | Sensitive customer data passed in tool arguments is written to application logs. | **Privacy-Preserving Hashing**: `McpProxyService` never stores raw arguments or results; it computes `SHA256(tool_args)` and structural metadata (`arg_keys`, `arg_count`). |
| **TR-007** | **Orphaned Ephemeral Agent Credentials** | Short-lived task agents retain valid credentials after task completion. | **Just-In-Time (JIT) Ephemeral TTL**: Ephemeral agents (`is_ephemeral=True`) enforce a strict `decommission_at` ceiling (`AgentService.jit_activate`). |

---

## 2. SHA256 Causal Hash Chain Verification

The audit log table (`audit_logs`) acts as an immutable ledger:

```
[Entry N-1] --(previous_hash)--> [Entry N: SHA256(content + previous_hash)] --(previous_hash)--> [Entry N+1]
```

To run an on-demand compliance audit, operators trigger `GET /api/v1/audit/verify`:
- The service walks the database rows sequentially from `sequence_number = 1`.
- If the recomputed hash does not match `entry_hash`, or if `previous_hash` does not match the preceding row's hash, the system raises an immediate alert with the exact broken sequence number.
