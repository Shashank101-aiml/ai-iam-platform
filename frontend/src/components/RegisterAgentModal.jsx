import React, { useState } from 'react';
import { Cpu, AlertOctagon, X } from 'lucide-react';
import { apiService } from '../services/api.js';

export default function RegisterAgentModal({ agents, onClose, onRegistered }) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [scopesInput, setScopesInput] = useState('tool:execute');
  const [parentAgentId, setParentAgentId] = useState('');
  const [maxDelegationDepth, setMaxDelegationDepth] = useState(3);
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
      await apiService.registerAgent({
        name,
        description,
        allowedScopes,
        parentAgentId: parentAgentId || null,
        maxDelegationDepth: Number(maxDelegationDepth),
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
      <div className="glass-panel w-full max-w-[560px] p-8" style={{ border: '1px solid var(--color-border-accent)' }}>
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
