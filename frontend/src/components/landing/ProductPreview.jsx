import React from 'react';
import { Cpu, CheckCircle, Clock, Shield, Key } from 'lucide-react';

// A static mockup built from the SAME classes/tokens as the real
// (restyled) dashboard — not a screenshot. Kept truthful and never
// goes stale, at the cost of not being pixel-identical to the live
// app; revisit with a real screenshot once the dashboard has settled.
const MOCK_AGENTS = [
  { name: 'Orchestrator Agent', status: 'ACTIVE', scopes: ['agent:delegate', 'tool:execute'] },
  { name: 'Data Analytics Sub-Agent', status: 'ACTIVE', scopes: ['tool:execute'] },
  { name: 'JIT Vulnerability Scanner', status: 'PENDING', scopes: ['tool:execute'] },
];

export default function ProductPreview() {
  return (
    <section className="max-w-6xl mx-auto px-6 py-24">
      <div className="text-center max-w-2xl mx-auto mb-14">
        <h2 className="font-outfit text-3xl md:text-4xl font-bold text-ink-900 mb-4">
          The same console your operators actually use
        </h2>
        <p className="text-ink-600 text-lg">
          Agent lifecycle, delegation chains, the audit ledger, and MCP proxy
          decisions — one governance console, live against your real backend.
        </p>
      </div>

      {/* Browser-chrome frame */}
      <div className="rounded-2xl overflow-hidden shadow-2xl border border-surface-100 max-w-4xl mx-auto">
        <div className="bg-surface-100 px-4 py-3 flex items-center gap-2">
          <span className="w-3 h-3 rounded-full bg-rose-400" />
          <span className="w-3 h-3 rounded-full bg-amber-400" />
          <span className="w-3 h-3 rounded-full bg-emerald-400" />
          <span className="ml-3 text-xs text-ink-600 font-mono">ai-iam.internal/dashboard</span>
        </div>

        <div className="p-6" style={{ background: 'var(--color-surface-50)' }}>
          <div className="flex gap-3 overflow-x-auto">
            {MOCK_AGENTS.map((agent) => {
              const isActive = agent.status === 'ACTIVE';
              return (
                <div
                  key={agent.name}
                  className={`glass-panel p-4 min-w-[220px] border-l-4 ${isActive ? 'border-l-emerald-500' : 'border-l-amber-500'}`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${isActive ? 'bg-emerald-500/15' : 'bg-amber-500/15'}`}>
                      <Cpu size={16} className={isActive ? 'text-emerald-600' : 'text-amber-600'} />
                    </div>
                    <span className={`badge ${isActive ? 'badge-active' : 'badge-pending'} text-[0.6rem]`}>
                      {isActive ? <CheckCircle size={10} /> : <Clock size={10} />}
                      {agent.status}
                    </span>
                  </div>
                  <div className="font-outfit text-sm font-semibold text-ink-900 mb-2">{agent.name}</div>
                  <div className="flex flex-wrap gap-1 mb-3">
                    {agent.scopes.map((s) => (
                      <span key={s} className="font-mono text-[0.62rem] bg-brand-red/8 text-brand-red px-1.5 py-0.5 rounded">
                        {s}
                      </span>
                    ))}
                  </div>
                  <button className="btn-primary w-full text-[0.72rem] py-1.5 flex items-center justify-center gap-1.5" disabled>
                    {isActive ? <Key size={12} /> : <Shield size={12} />}
                    {isActive ? 'Issue API Key' : 'Activate'}
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
}
