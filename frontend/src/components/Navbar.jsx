import React, { useState } from 'react';
import { ShieldCheck, Lock, Activity, CheckCircle2, AlertTriangle, Cpu } from 'lucide-react';

export default function Navbar({ onVerify, verificationStatus }) {
  const [verifying, setVerifying] = useState(false);

  const handleVerifyClick = async () => {
    setVerifying(true);
    await onVerify();
    setVerifying(false);
  };

  return (
    <header
      className="glass-panel"
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0.85rem 2rem',
        borderBottom: '1px solid var(--color-border-glass)',
        borderRadius: 0,
        position: 'sticky',
        top: 0,
        zIndex: 50,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
        <div
          style={{
            background: 'linear-gradient(135deg, #00f5ff 0%, #1e3a8a 100%)',
            padding: '0.5rem',
            borderRadius: '10px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 16px rgba(0, 245, 255, 0.4)',
          }}
        >
          <ShieldCheck size={24} color="#060b19" strokeWidth={2.5} />
        </div>
        <div>
          <h1 className="font-outfit" style={{ fontSize: '1.25rem', fontWeight: 700, letterSpacing: '-0.02em', color: '#fff' }}>
            AI-IAM <span style={{ color: '#00f5ff', fontWeight: 600 }}>PLATFORM</span>
          </h1>
          <span style={{ fontSize: '0.7rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            Auth0 for AI Agents • SPIFFE/OPA ReBAC Governed
          </span>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
        {/* Verification Trigger & Status Pill */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {verificationStatus && (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                padding: '0.35rem 0.75rem',
                borderRadius: '8px',
                background: verificationStatus.chain_valid
                  ? 'rgba(16, 185, 129, 0.15)'
                  : 'rgba(244, 63, 94, 0.2)',
                border: `1px solid ${
                  verificationStatus.chain_valid ? '#10b981' : '#f43f5e'
                }`,
                fontSize: '0.8rem',
                fontWeight: 600,
              }}
            >
              {verificationStatus.chain_valid ? (
                <>
                  <CheckCircle2 size={15} color="#10b981" />
                  <span style={{ color: '#34d399' }}>
                    SHA256 Hash Chain Verified ({verificationStatus.total_entries_checked} entries)
                  </span>
                </>
              ) : (
                <>
                  <AlertTriangle size={15} color="#f43f5e" />
                  <span style={{ color: '#fb7185' }}>
                    Tamper Detected @ Sequence #{verificationStatus.broken_at_sequence}
                  </span>
                </>
              )}
            </div>
          )}

          <button
            onClick={handleVerifyClick}
            disabled={verifying}
            className="btn-secondary"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              fontSize: '0.85rem',
              padding: '0.5rem 1rem',
            }}
          >
            <Activity size={16} className={verifying ? 'animate-pulse-glow' : ''} color="#00f5ff" />
            <span>{verifying ? 'Verifying Chain...' : 'Verify Audit Integrity'}</span>
          </button>
        </div>

        {/* Operator Profile */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.6rem',
            borderLeft: '1px solid var(--color-border-glass)',
            paddingLeft: '1.5rem',
          }}
        >
          <div
            style={{
              width: '36px',
              height: '36px',
              borderRadius: '50%',
              background: 'rgba(0, 245, 255, 0.15)',
              border: '1px solid var(--color-border-accent)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Cpu size={18} color="#00f5ff" />
          </div>
          <div>
            <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#f8fafc' }}>admin@acmecorp.ai</div>
            <div style={{ fontSize: '0.7rem', color: '#34d399', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#34d399', display: 'inline-block' }}></span>
              Superuser Operator
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}
