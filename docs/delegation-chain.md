# Multi-Hop Delegation & Scope Attenuation

In autonomous agentic workflows, top-level supervisor agents frequently spawn sub-agents to execute specialized tasks. The AI-IAM Platform governs this trust chain via **Multi-Hop Delegation Grants**.

---

## 1. Scope Attenuation Principle

Mathematical scope attenuation ensures that **no delegatee agent can ever hold more privileges than its delegator**:

$$\text{Scopes}_{\text{delegatee}} \subseteq \text{Scopes}_{\text{delegator}}$$

If an agent attempts to delegate a scope it does not possess (`DelegationService.delegate`), the request is immediately rejected with `HTTP 422 Unprocessable Entity`:

```json
{
  "detail": "Requested scopes exceed delegator's active scopes: {'super:admin'}"
}
```

---

## 2. Delegation Depth Ceiling (`MAX_DELEGATION_DEPTH`)

To prevent infinite privilege delegation loops or rogue runaway multi-agent chains, the platform enforces a strict tree depth limit:

```mermaid
graph LR
    A[Supervisor Agent<br>Depth: 0] -->|Delegates| B[Sub-Agent Level 1<br>Depth: 1]
    B -->|Delegates| C[Sub-Agent Level 2<br>Depth: 2]
    C -.->|BLOCKED if Max=2| D[Sub-Agent Level 3<br>Depth: 3 (HTTP 403)]
```

Every agent record has a `max_delegation_depth` attribute (defaulting to `settings.MAX_DELEGATION_DEPTH = 5`). During delegation grant issuance (`/api/v1/token/delegate`), the service verifies:

$$\text{Current Depth} + 1 \le \text{Max Delegation Depth}$$

If violated, the delegation attempt is blocked (`HTTP 403 Forbidden`).

---

## 3. Delegation Token Exchange (`DelegationGrant`)

When a delegation grant is successfully created:
1. A `DelegationGrant` row is persisted with a unique JWT ID (`delegation_jti`).
2. A short-lived RS256 token (`delegation_token`) is returned to the delegatee.
3. Every downstream request from the delegatee includes this token, allowing `AgentAuthMiddleware` and `McpProxyService` to verify the exact causal chain (`causal_trace_id`) right back to the root task orchestrator.
