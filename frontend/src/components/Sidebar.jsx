import React from 'react';
import { Cpu, GitBranch, ShieldAlert, Terminal, Layers } from 'lucide-react';

export default function Sidebar({ activeTab, onTabChange }) {
  const navItems = [
    { id: 'agents', label: 'Agent Hierarchy Tree', icon: Cpu, badge: 'Phase 1-3' },
    { id: 'delegation', label: 'Multi-Hop Delegation', icon: GitBranch, badge: 'ReBAC' },
    { id: 'audit', label: 'Append-Only Ledger', icon: ShieldAlert, badge: 'SHA256' },
    { id: 'mcp', label: 'Pre-Execution Proxy', icon: Terminal, badge: 'OPA Deny' },
  ];

  return (
    <aside
      className="glass-panel"
      style={{
        width: '260px',
        borderRight: '1px solid var(--color-border-glass)',
        borderTop: 'none',
        borderBottom: 'none',
        borderLeft: 'none',
        borderRadius: 0,
        padding: '1.5rem 1rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '2rem',
      }}
    >
      <div>
        <div
          style={{
            fontSize: '0.7rem',
            fontWeight: 700,
            textTransform: 'uppercase',
            letterSpacing: '0.1em',
            color: 'var(--color-text-muted)',
            marginBottom: '0.75rem',
            paddingLeft: '0.5rem',
          }}
        >
          Governance Modules
        </div>
        <nav style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onTabChange(item.id)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '0.75rem 0.85rem',
                  borderRadius: '10px',
                  background: isActive ? 'rgba(0, 245, 255, 0.15)' : 'transparent',
                  border: isActive ? '1px solid var(--color-border-accent)' : '1px solid transparent',
                  color: isActive ? '#fff' : 'var(--color-text-muted)',
                  cursor: 'pointer',
                  transition: 'all 0.2s ease',
                  textAlign: 'left',
                  fontSize: '0.88rem',
                  fontWeight: isActive ? 600 : 500,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <Icon size={18} color={isActive ? '#00f5ff' : '#94a3b8'} />
                  <span>{item.label}</span>
                </div>
                <span
                  style={{
                    fontSize: '0.65rem',
                    padding: '0.15rem 0.45rem',
                    borderRadius: '4px',
                    background: isActive ? '#00f5ff' : 'rgba(255,255,255,0.06)',
                    color: isActive ? '#060b19' : '#94a3b8',
                    fontWeight: 700,
                  }}
                >
                  {item.badge}
                </span>
              </button>
            );
          })}
        </nav>
      </div>

      <div
        className="glass-panel"
        style={{
          marginTop: 'auto',
          padding: '1rem',
          background: 'rgba(10, 17, 40, 0.8)',
          border: '1px solid rgba(0, 245, 255, 0.15)',
          borderRadius: '10px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
          <Layers size={16} color="#00f5ff" />
          <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#f8fafc' }}>SPIRE Trust Domain</span>
        </div>
        <p className="font-mono" style={{ fontSize: '0.72rem', color: '#00f5ff', wordBreak: 'break-all' }}>
          spiffe://ai-iam.internal
        </p>
        <div style={{ fontSize: '0.68rem', color: 'var(--color-text-muted)', marginTop: '0.4rem' }}>
          Workload mTLS Attestation Active
        </div>
      </div>
    </aside>
  );
}
