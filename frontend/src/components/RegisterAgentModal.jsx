import React, { useState } from 'react';
import { Cpu, AlertOctagon, X } from 'lucide-react';
import { apiService } from '../services/api.js';

// Three bindings against the bundled mock MCP server (docker-compose's
// mock-mcp service): a plain data server, a web-search server marked as an
// untrusted source, and a mail server whose send_email is tagged as an
// external_send capability — enough to exercise tool_filter, OPA's blocked
// tools, and provenance-aware denial.
const DEMO_BINDINGS = [
  { server_id: 'data-mcp', server_url: 'http://mock-mcp:8080', tool_filter: ['query_database'] },
  { server_id: 'web-mcp', server_url: 'http://mock-mcp:8080', tool_filter: ['search_web'], untrusted_source: true },
  {
    server_id: 'mail-mcp',
    server_url: 'http://mock-mcp:8080',
    tool_filter: ['send_email'],
    tool_capabilities: { send_email: ['external_send'] },
  },
];

function parseBindings(text) {
  if (!text.trim()) return [];
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error('MCP bindings is not valid JSON.');
  }
  if (!Array.isArray(parsed) || parsed.some((b) => typeof b !== 'object' || b === null || Array.isArray(b))) {
    throw new Error('MCP bindings must be a JSON array of objects.');
  }
  return parsed;
}

export default function RegisterAgentModal({ agents, onClose, onRegistered }) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [scopesInput, setScopesInput] = useState('tool:execute');
  const [parentAgentId, setParentAgentId] = useState('');
  const [maxDelegationDepth, setMaxDelegationDepth] = useState(3);
  const [bindingsInput, setBindingsInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const allowedScopes = scopesInput
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const mcpBindings = parseBindings(bindingsInput);
      await apiService.registerAgent({
        name,
        description,
        allowedScopes,
        parentAgentId: parentAgentId || null,
        maxDelegationDepth: Number(maxDelegationDepth),
        mcpBindings,
      });
      await onRegistered();
      onClose();
    } catch (err) {
      setError(err.message || 'Failed to register agent.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-bg-deep/85 backdrop-blur-sm flex items-center justify-center z-[100] p-4">
      <div className="glass-panel w-full max-w-[560px] max-h-[92vh] overflow-y-auto p-8" style={{ border: '1px solid var(--color-border-accent)' }}>
        <div className="flex justify-between items-center mb-6">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-[10px] bg-brand-red/10 border border-border-accent">
              <Cpu size={20} className="text-brand-red" />
            </div>
            <div>
              <h3 className="font-outfit text-xl font-bold text-ink-900">
                Register New Agent
              </h3>
              <span className="text-[0.78rem] text-text-muted">Starts in PENDING — activate it afterward</span>
            </div>
          </div>
          <button onClick={onClose} className="text-text-muted hover:text-ink-900 bg-transparent border-none cursor-pointer">
            <X size={20} />
          </button>
        </div>

        {error && (
          <div className="flex items-start gap-3 p-3.5 mb-5 rounded-lg border border-rose-300" style={{ background: '#fff1f2' }} role="alert">
            <AlertOctagon size={18} className="text-rose-600 shrink-0 mt-0.5" />
            <p className="text-sm" style={{ color: '#be123c' }}>{error}</p>
          </div>
        )}

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div>
            <label htmlFor="agentName" className="block text-sm font-semibold text-slate-700 mb-1.5">
              Agent name
            </label>
            <input
              id="agentName"
              type="text"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Analytics Sub-Agent"
              className="w-full p-3 rounded-lg bg-surface-100 border border-slate-200 text-ink-900 text-sm outline-none focus:border-brand-red"
            />
          </div>

          <div>
            <label htmlFor="agentDescription" className="block text-sm font-semibold text-slate-700 mb-1.5">
              Description <span className="font-normal text-text-muted">(optional)</span>
            </label>
            <input
              id="agentDescription"
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="What this agent does"
              className="w-full p-3 rounded-lg bg-surface-100 border border-slate-200 text-ink-900 text-sm outline-none focus:border-brand-red"
            />
          </div>

          <div>
            <label htmlFor="agentScopes" className="block text-sm font-semibold text-slate-700 mb-1.5">
              Allowed ReBAC scopes <span className="font-normal text-text-muted">(comma-separated)</span>
            </label>
            <input
              id="agentScopes"
              type="text"
              value={scopesInput}
              onChange={(e) => setScopesInput(e.target.value)}
              placeholder="tool:execute, agent:delegate"
              className="w-full p-3 rounded-lg bg-surface-100 border border-slate-200 text-ink-900 text-sm font-mono outline-none focus:border-brand-red"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label htmlFor="parentAgent" className="block text-sm font-semibold text-slate-700 mb-1.5">
                Parent agent <span className="font-normal text-text-muted">(optional)</span>
              </label>
              <select
                id="parentAgent"
                value={parentAgentId}
                onChange={(e) => setParentAgentId(e.target.value)}
                className="w-full p-3 rounded-lg bg-surface-100 border border-slate-200 text-ink-900 text-sm"
              >
                <option value="">None (top-level)</option>
                {agents.map((a) => (
                  <option key={a.id} value={a.id}>{a.name}</option>
                ))}
              </select>
            </div>
            <div>
              <label htmlFor="maxDepth" className="block text-sm font-semibold text-slate-700 mb-1.5">
                Max delegation depth
              </label>
              <input
                id="maxDepth"
                type="number"
                min={1}
                max={10}
                value={maxDelegationDepth}
                onChange={(e) => setMaxDelegationDepth(e.target.value)}
                className="w-full p-3 rounded-lg bg-surface-100 border border-slate-200 text-ink-900 text-sm outline-none focus:border-brand-red"
              />
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label htmlFor="mcpBindings" className="block text-sm font-semibold text-slate-700">
                MCP server bindings <span className="font-normal text-text-muted">(optional, JSON)</span>
              </label>
              <button
                type="button"
                onClick={() => setBindingsInput(JSON.stringify(DEMO_BINDINGS, null, 2))}
                className="text-xs font-semibold text-brand-red hover:underline"
              >
                Insert demo bindings
              </button>
            </div>
            <textarea
              id="mcpBindings"
              rows={bindingsInput ? 8 : 3}
              value={bindingsInput}
              onChange={(e) => setBindingsInput(e.target.value)}
              placeholder='[{"server_id": "data-mcp", "server_url": "http://mock-mcp:8080"}]'
              spellCheck={false}
              className="w-full p-3 rounded-lg bg-surface-100 border border-slate-200 text-ink-900 text-xs font-mono outline-none focus:border-brand-red"
            />
            <p className="text-xs text-text-muted mt-1">
              Which MCP servers this agent may reach. Only hosts on the platform's allowlist are accepted.
            </p>
          </div>

          <div className="flex gap-3 justify-end mt-2">
            <button type="button" onClick={onClose} className="btn-secondary">Cancel</button>
            <button type="submit" disabled={loading} className="btn-primary">
              {loading ? 'Registering...' : 'Register Agent'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
