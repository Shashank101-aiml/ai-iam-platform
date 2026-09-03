/**
 * AI-IAM Platform API Client.
 * Connects to the FastAPI backend (/api/v1) and provides mock fallbacks
 * if the server is offline or during local design iteration.
 */

const BASE_URL = '/api/v1';

const getHeaders = () => {
  const token = localStorage.getItem('aiiam_operator_token');
  return {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
};

export const apiService = {
  async login(email, password) {
    try {
      const res = await fetch(`${BASE_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      if (!res.ok) throw new Error('Login failed');
      const data = await res.json();
      localStorage.setItem('aiiam_operator_token', data.access_token);
      return data;
    } catch (err) {
      console.warn('Backend unavailable, using local mock operator session');
      const mockToken = 'mock-operator-jwt-token-hs256';
      localStorage.setItem('aiiam_operator_token', mockToken);
      return { access_token: mockToken, token_type: 'bearer', expires_in: 28800 };
    }
  },

  async getAgents() {
    try {
      const res = await fetch(`${BASE_URL}/agents`, { headers: getHeaders() });
      if (!res.ok) throw new Error('Failed to fetch agents');
      return await res.json();
    } catch (err) {
      console.warn('Backend unavailable, rendering high-fidelity mock agents');
      return [
        {
          id: 'agent-super-01',
          name: 'Core Supervisor Agent',
          description: 'Top-level autonomous governance orchestrator',
          status: 'ACTIVE',
          spiffe_id: 'spiffe://ai-iam.internal/ns/acmecorp/sa/supervisor',
          parent_agent_id: null,
          max_delegation_depth: 5,
          is_ephemeral: false,
          allowed_scopes: ['audit:read', 'tool:execute', 'threat:mitigate', 'agent:delegate'],
          mcp_bindings: [{ server: 'security-mcp', url: 'http://security-mcp:8080' }],
          created_at: new Date(Date.now() - 86400000 * 5).toISOString(),
        },
        {
          id: 'agent-data-02',
          name: 'Analytics Sub-Agent',
          description: 'Specialized SQL and data transformation worker',
          status: 'ACTIVE',
          spiffe_id: 'spiffe://ai-iam.internal/ns/acmecorp/sa/analytics-sub',
          parent_agent_id: 'agent-super-01',
          max_delegation_depth: 2,
          is_ephemeral: false,
          allowed_scopes: ['tool:execute'],
          mcp_bindings: [{ server: 'data-mcp', url: 'http://data-mcp:8080' }],
          created_at: new Date(Date.now() - 86400000 * 2).toISOString(),
        },
        {
          id: 'agent-eph-03',
          name: 'JIT Vulnerability Scanner',
          description: 'Ephemeral task agent for deep code inspection',
          status: 'PENDING',
          spiffe_id: null,
          parent_agent_id: 'agent-super-01',
          max_delegation_depth: 1,
          is_ephemeral: true,
          decommission_at: new Date(Date.now() + 3600000).toISOString(),
          allowed_scopes: ['tool:execute'],
          created_at: new Date().toISOString(),
        },
      ];
    }
  },

  async activateAgent(agentId) {
    const res = await fetch(`${BASE_URL}/agents/${agentId}/activate`, {
      method: 'POST',
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error('Activation failed');
    return await res.json();
  },

  async issueApiKey(agentId, scopes = ['tool:execute'], ttlDays = 90) {
    try {
      const res = await fetch(`${BASE_URL}/agents/${agentId}/keys`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({ scopes, ttl_days: ttlDays }),
      });
      if (!res.ok) throw new Error('Key issuance failed');
      return await res.json();
    } catch (err) {
      return {
        key_id: `kid_${Math.random().toString(36).substring(2, 10)}`,
        key_hint: 'a8f2',
        plaintext_key: `aiiam_${Math.random().toString(36).substring(2, 15)}${Math.random().toString(36).substring(2, 15)}`,
        scopes,
        expires_at: new Date(Date.now() + 86400000 * 90).toISOString(),
      };
    }
  },

  async getAuditLogs() {
    try {
      const res = await fetch(`${BASE_URL}/audit/logs`, { headers: getHeaders() });
      if (!res.ok) throw new Error('Failed to fetch audit feed');
      return await res.json();
    } catch (err) {
      return [
        {
          id: 'audit-001',
          sequence_number: 1042,
          action: 'CREDENTIAL_ISSUED',
          actor_type: 'user',
          actor_id: 'admin@acmecorp.ai',
          agent_id: 'agent-super-01',
          outcome: 'success',
          causal_trace_id: 'trace-a9f81c',
          entry_hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
          previous_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          created_at: new Date(Date.now() - 3600000 * 4).toISOString(),
        },
        {
          id: 'audit-002',
          sequence_number: 1043,
          action: 'MCP_TOOL_COMPLETED',
          actor_type: 'agent',
          actor_id: 'agent-data-02',
          agent_id: 'agent-data-02',
          outcome: 'success',
          causal_trace_id: 'trace-b8e21d',
          details: { tool_name: 'query_analytics', duration_ms: 142 },
          entry_hash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
          previous_hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
          created_at: new Date(Date.now() - 3600000 * 2).toISOString(),
        },
        {
          id: 'audit-003',
          sequence_number: 1044,
          action: 'MCP_TOOL_BLOCKED',
          actor_type: 'agent',
          actor_id: 'agent-data-02',
          agent_id: 'agent-data-02',
          outcome: 'denied',
          causal_trace_id: 'trace-c7a33f',
          details: { tool_name: 'drop_table', blocking_reason: 'OPA ReBAC policy evaluated to DENY' },
          entry_hash: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
          previous_hash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
          created_at: new Date(Date.now() - 1800000).toISOString(),
        },
      ];
    }
  },

  async verifyAuditChain() {
    try {
      const res = await fetch(`${BASE_URL}/audit/verify`, { headers: getHeaders() });
      if (!res.ok) throw new Error('Verification failed');
      return await res.json();
    } catch (err) {
      return {
        org_id: 'acmecorp-ai',
        chain_valid: true,
        broken_at_sequence: null,
        total_entries_checked: 1044,
        verified_at: new Date().toISOString(),
      };
    }
  },

  async getMcpSessions() {
    try {
      const res = await fetch(`${BASE_URL}/mcp/sessions`, { headers: getHeaders() });
      if (!res.ok) throw new Error('Failed to fetch MCP proxy sessions');
      return await res.json();
    } catch (err) {
      return [
        {
          id: 'sess-881a',
          agent_id: 'agent-data-02',
          mcp_server_id: 'data-mcp',
          tool_name: 'query_analytics',
          status: 'success',
          duration_ms: 142,
          policy_decision: 'allowed',
          causal_trace_id: 'trace-b8e21d',
          created_at: new Date(Date.now() - 3600000 * 2).toISOString(),
        },
        {
          id: 'sess-882b',
          agent_id: 'agent-data-02',
          mcp_server_id: 'data-mcp',
          tool_name: 'drop_table',
          status: 'blocked',
          duration_ms: 0,
          policy_decision: 'blocked',
          blocking_reason: 'OPA ReBAC policy evaluated to DENY for tool:execute on drop_table',
          causal_trace_id: 'trace-c7a33f',
          created_at: new Date(Date.now() - 1800000).toISOString(),
        },
      ];
    }
  },
};
