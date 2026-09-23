import React from 'react';
import { Cpu, GitBranch, ShieldAlert, Terminal, Layers, X } from 'lucide-react';

const formatCount = (n) => new Intl.NumberFormat('en', { notation: 'compact' }).format(n);

// counts is null until the first successful fetch, and again whenever a
// fetch fails — a badge is either a real number or absent, never a stale or
// made-up one (same no-mock rule as the rest of the dashboard).
export default function Sidebar({ activeTab, onTabChange, isOpen, onClose, counts }) {
  const navItems = [
    {
      id: 'agents', label: 'Agent Hierarchy Tree', icon: Cpu,
      count: counts?.agents,
      hint: (n) => `${n} agents in this organization`,
    },
    {
      id: 'delegation', label: 'Multi-Hop Delegation', icon: GitBranch,
      count: counts?.sub_agents,
      hint: (n) => `${n} sub-agents in the delegation tree`,
    },
    {
      id: 'audit', label: 'Append-Only Ledger', icon: ShieldAlert,
      count: counts?.audit_entries,
      hint: (n) => `${n} entries in the audit hash chain`,
    },
    {
      id: 'mcp', label: 'Pre-Execution Proxy', icon: Terminal,
      count: counts?.mcp_calls,
      hint: (n) => `${n} proxied tool calls, ${counts.mcp_blocked} blocked before execution`,
    },
  ];

  const content = (
    <>
      <div>
        <div className="flex items-center justify-between mb-3 pl-2 md:hidden">
          <span className="text-xs font-bold uppercase tracking-[0.1em] text-text-muted">
            Governance Modules
          </span>
          <button onClick={onClose} className="text-text-muted hover:text-ink-900" aria-label="Close menu">
            <X size={20} />
          </button>
        </div>
        <div className="hidden md:block text-xs font-bold uppercase tracking-[0.1em] text-text-muted mb-3 pl-2">
          Governance Modules
        </div>
        <nav className="flex flex-col gap-1.5">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onTabChange(item.id)}
                className={`flex items-center justify-between px-3.5 py-3 rounded-[10px] text-left text-[0.88rem] transition-all ${
                  isActive
                    ? 'bg-brand-red/8 border border-border-accent text-ink-900 font-semibold'
                    : 'border border-transparent text-text-muted font-medium hover:bg-slate-100'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Icon size={18} className={isActive ? 'text-brand-red' : 'text-text-muted'} />
                  <span>{item.label}</span>
                </div>
                {typeof item.count === 'number' && (
                  <span
                    title={item.hint(item.count)}
                    aria-label={item.hint(item.count)}
                    className={`text-[0.7rem] px-2 py-0.5 rounded-full font-bold tabular-nums whitespace-nowrap ${
                      isActive ? 'bg-brand-red/10 text-brand-red' : 'bg-slate-100 text-text-muted'
                    }`}
                  >
                    {formatCount(item.count)}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      <div className="glass-panel mt-auto p-4 rounded-[10px]" style={{ background: 'var(--color-surface-100)', border: '1px solid var(--color-border-glass)' }}>
        <div className="flex items-center gap-2 mb-1.5">
          <Layers size={16} className="text-brand-red" />
          <span className="text-sm font-semibold text-ink-900">Agent Identifier Namespace</span>
        </div>
        <p className="font-mono text-xs text-brand-red break-all">
          spiffe://ai-iam.internal
        </p>
        {/* No SPIRE server, no X.509 cert, no mTLS — this is a
            format-checked identifier string, not a workload
            attestation (Slice 16; see backend/app/core/spiffe.py's
            module docstring for the full explanation). */}
        <div className="text-[0.68rem] text-text-muted mt-1.5">
          SPIFFE-style URI format, not certificate-based attestation
        </div>
      </div>
    </>
  );

  return (
    <>
      {/* Desktop: static column */}
      <aside className="hidden md:flex glass-panel w-[260px] rounded-none border-y-0 border-l-0 p-6 flex-col gap-8">
        {content}
      </aside>

      {/* Mobile: slide-over drawer */}
      {isOpen && (
        <div className="md:hidden fixed inset-0 z-40 flex">
          <div className="absolute inset-0 bg-black/60" onClick={onClose} />
          <aside className="relative glass-panel w-[280px] max-w-[80vw] h-full p-6 flex flex-col gap-8 rounded-none">
            {content}
          </aside>
        </div>
      )}
    </>
  );
}
