import React, { useState } from 'react';
import { ShieldCheck, Activity, CheckCircle2, AlertTriangle, Cpu, Menu, LogOut } from 'lucide-react';

export default function Navbar({ onVerify, verificationStatus, operator, onLogout, onToggleSidebar }) {
  const [verifying, setVerifying] = useState(false);

  const handleVerifyClick = async () => {
    setVerifying(true);
    await onVerify();
    setVerifying(false);
  };

  return (
    <header className="glass-panel flex items-center justify-between gap-3 px-4 md:px-8 py-3 rounded-none border-x-0 border-t-0 sticky top-0 z-50">
      <div className="flex items-center gap-3">
        <button
          onClick={onToggleSidebar}
          className="md:hidden text-text-muted hover:text-ink-900"
          aria-label="Toggle navigation"
        >
          <Menu size={22} />
        </button>

        <div className="bg-gradient-to-br from-cyan-glow to-sapphire p-2 rounded-[10px] flex items-center justify-center shadow-[0_0_16px_rgba(200,16,46,0.3)]">
          <ShieldCheck size={24} className="text-bg-deep" strokeWidth={2.5} />
        </div>
        <div>
          <h1 className="font-outfit text-lg md:text-xl font-bold tracking-tight text-ink-900">
            AI-IAM <span className="text-brand-red font-semibold">PLATFORM</span>
          </h1>
          <span className="hidden sm:block text-[0.7rem] text-text-muted uppercase tracking-[0.08em]">
            Auth0 for AI Agents • SPIFFE/OPA ReBAC Governed
          </span>
        </div>
      </div>

      <div className="flex items-center gap-3 md:gap-6">
        {/* Verification Trigger & Status Pill */}
        <div className="hidden sm:flex items-center gap-3">
          {verificationStatus && (
            <div
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-semibold"
              style={{
                background: verificationStatus.chain_valid ? '#ecfdf5' : '#fff1f2',
                border: `1px solid ${verificationStatus.chain_valid ? '#a7f3d0' : '#fecdd3'}`,
              }}
            >
              {verificationStatus.chain_valid ? (
                <>
                  <CheckCircle2 size={15} className="text-emerald" />
                  <span style={{ color: '#047857' }}>
                    SHA256 Hash Chain Verified ({verificationStatus.total_entries_checked} entries)
                  </span>
                </>
              ) : (
                <>
                  <AlertTriangle size={15} className="text-rose" />
                  <span style={{ color: '#be123c' }}>
                    Tamper Detected @ Sequence #{verificationStatus.broken_at_sequence}
                  </span>
                </>
              )}
            </div>
          )}

          <button
            onClick={handleVerifyClick}
            disabled={verifying}
            className="btn-secondary flex items-center gap-2 text-sm py-2 px-4"
          >
            <Activity size={16} className={`text-brand-red ${verifying ? 'animate-pulse-glow' : ''}`} />
            <span>{verifying ? 'Verifying Chain...' : 'Verify Audit Integrity'}</span>
          </button>
        </div>

        {/* Operator Profile — real identity from GET /auth/me (frontend overhaul),
            not the hardcoded placeholder this used to show. */}
        <div className="flex items-center gap-2 md:gap-3 border-l border-border-glass pl-3 md:pl-6">
          <div className="w-9 h-9 rounded-full bg-brand-red/10 border border-border-accent flex items-center justify-center shrink-0">
            <Cpu size={18} className="text-brand-red" />
          </div>
          <div className="hidden sm:block">
            <div className="text-sm font-semibold text-ink-900 truncate max-w-[160px]">
              {operator?.email || 'Loading…'}
            </div>
            <div className="text-[0.7rem] text-emerald-600 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-600 inline-block" />
              {operator?.is_superuser ? 'Superuser Operator' : 'Operator'}
            </div>
          </div>
          <button
            onClick={onLogout}
            className="text-text-muted hover:text-rose transition-colors"
            title="Log out"
            aria-label="Log out"
          >
            <LogOut size={18} />
          </button>
        </div>
      </div>
    </header>
  );
}
