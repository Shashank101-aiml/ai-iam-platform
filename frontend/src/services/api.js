/**
 * AI-IAM Platform API Client.
 * Connects to the FastAPI backend (/api/v1). No mock fallbacks (Slice
 * 16) — a governance dashboard that invents plausible agents and audit
 * rows when the backend is unreachable is worse than one showing an
 * explicit error: an operator relying on this to check whether a
 * delegation chain or an audit trail is actually sound must never be
 * shown fabricated data that happens to look legitimate. Every method
 * here either returns real backend data or throws — callers (App.jsx)
 * are responsible for surfacing that as a visible error state, not for
 * silently falling back to something that renders anyway.
 */

const BASE_URL = '/api/v1';

const getHeaders = () => {
  const token = localStorage.getItem('aiiam_operator_token');
  return {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
};

async function requestJson(path, options = {}) {
  let res;
  try {
    res = await fetch(`${BASE_URL}${path}`, options);
  } catch (err) {
    // fetch() itself throws on a network-level failure (backend down,
    // DNS, CORS preflight rejected) — surface that distinctly from an
    // HTTP error response, since there's no status code to report.
    throw new Error(`Cannot reach the AI-IAM backend at ${BASE_URL}${path}: ${err.message}`);
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail ? JSON.stringify(body.detail) : detail;
    } catch {
      // Response wasn't JSON — fall back to the status text already set above.
    }
    throw new Error(`${path} failed (${res.status}): ${detail}`);
  }
  return res.json();
}

export const apiService = {
  async getCurrentUser() {
    return requestJson('/auth/me', { headers: getHeaders() });
  },

  async login(email, password) {
    const data = await requestJson('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    localStorage.setItem('aiiam_operator_token', data.access_token);
    return data;
  },

  async trialSignup(orgName, email, password) {
    const data = await requestJson('/auth/trial-signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ org_name: orgName, admin_email: email, admin_password: password }),
    });
    localStorage.setItem('aiiam_operator_token', data.access_token);
    return data;
  },

  async getAgents() {
    return requestJson('/agents', { headers: getHeaders() });
  },

  async registerAgent({ name, description, allowedScopes, parentAgentId, maxDelegationDepth }) {
    return requestJson('/agents', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({
        name,
        description: description || null,
        allowed_scopes: allowedScopes,
        parent_agent_id: parentAgentId || null,
        max_delegation_depth: maxDelegationDepth,
      }),
    });
  },

  async activateAgent(agentId) {
    return requestJson(`/agents/${agentId}/activate`, {
      method: 'POST',
      headers: getHeaders(),
    });
  },

  async issueApiKey(agentId, scopes = ['tool:execute'], ttlDays = 90) {
    return requestJson(`/agents/${agentId}/keys`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ scopes, ttl_days: ttlDays }),
    });
  },

  async getAuditLogs() {
    return requestJson('/audit/logs', { headers: getHeaders() });
  },

  async verifyAuditChain() {
    return requestJson('/audit/verify', { headers: getHeaders() });
  },

  async getMcpSessions() {
    return requestJson('/mcp/sessions', { headers: getHeaders() });
  },
};
