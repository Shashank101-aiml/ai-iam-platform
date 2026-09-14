import React, { useState } from 'react';
import { Key, ShieldAlert, Check, Copy, AlertTriangle, Clock, X } from 'lucide-react';
import { apiService } from '../services/api.js';

export default function ApiKeyModal({ agent, onClose }) {
  const [scopes, setScopes] = useState(agent.allowed_scopes || ['tool:execute']);
  const [ttlDays, setTtlDays] = useState(90);
  const [loading, setLoading] = useState(false);
  const [issuedKey, setIssuedKey] = useState(null);
  const [copied, setCopied] = useState(false);

  const handleIssue = async () => {
    setLoading(true);
    try {
      const res = await apiService.issueApiKey(agent.id, scopes, ttlDays);
      setIssuedKey(res);
    } catch (err) {
      console.error('Issue error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    if (issuedKey?.plaintext_key) {
      navigator.clipboard.writeText(issuedKey.plaintext_key);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    }
  };

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(6, 11, 25, 0.85)',
        backdropFilter: 'blur(8px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 100,
        padding: '1rem',
      }}
    >
      <div
        className="glass-panel"
        style={{
          width: '100%',
          maxWidth: '560px',
          padding: '2rem',
          background: 'rgba(10, 17, 40, 0.95)',
          border: '1px solid var(--color-border-accent)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div style={{ padding: '0.5rem', borderRadius: '10px', background: 'rgba(0, 245, 255, 0.15)', border: '1px solid var(--color-border-accent)' }}>
              <Key size={20} color="#00f5ff" />
            </div>
            <div>
              <h3 className="font-outfit" style={{ fontSize: '1.25rem', fontWeight: 700, color: '#fff' }}>
                Issue Zero-Downtime API Key
              </h3>
              <span style={{ fontSize: '0.78rem', color: 'var(--color-text-muted)' }}>Target: {agent.name}</span>
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        {!issuedKey ? (
          <div>
            <div style={{ marginBottom: '1.25rem' }}>
              <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#e2e8f0', marginBottom: '0.5rem' }}>
                ReBAC Scopes to Embed
              </label>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                {agent.allowed_scopes?.map((scope, idx) => (
                  <span
                    key={idx}
                    className="font-mono"
                    style={{
                      padding: '0.35rem 0.75rem',
                      borderRadius: '6px',
                      background: 'rgba(0, 245, 255, 0.12)',
                      color: '#00f5ff',
                      border: '1px solid rgba(0, 245, 255, 0.3)',
                      fontSize: '0.78rem',
                      fontWeight: 500,
                    }}
                  >
                    {scope}
                  </span>
                ))}
              </div>
            </div>

            <div style={{ marginBottom: '1.75rem' }}>
              <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#e2e8f0', marginBottom: '0.5rem' }}>
                Credential Expiration (`TTL Days`)
              </label>
              <select
                value={ttlDays}
                onChange={(e) => setTtlDays(Number(e.target.value))}
                style={{
                  width: '100%',
                  padding: '0.7rem',
                  borderRadius: '8px',
                  background: '#060b19',
                  border: '1px solid var(--color-border-glass)',
                  color: '#fff',
                  fontSize: '0.9rem',
                }}
              >
                <option value={30}>30 Days (Standard Worker)</option>
                <option value={90}>90 Days (Production Supervisor)</option>
                <option value={365}>365 Days (Long-Lived Credential)</option>
              </select>
            </div>

            <div
              style={{
                background: 'rgba(245, 158, 11, 0.12)',
                border: '1px solid rgba(245, 158, 11, 0.3)',
                padding: '0.85rem',
                borderRadius: '8px',
                display: 'flex',
                gap: '0.75rem',
                alignItems: 'flex-start',
                marginBottom: '1.75rem',
              }}
            >
              <AlertTriangle size={18} color="#fbbf24" style={{ flexShrink: 0, marginTop: '2px' }} />
              <p style={{ fontSize: '0.78rem', color: '#fde68a', lineHeight: 1.5 }}>
                <strong>Zero-Plaintext Security Policy:</strong> This key (`aiiam_...`) will be displayed exactly once. Only the `bcrypt` one-way hash (`hashed_secret`) is stored in PostgreSQL.
              </p>
            </div>

            <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'flex-end' }}>
              <button onClick={onClose} className="btn-secondary">Cancel</button>
              <button onClick={handleIssue} disabled={loading} className="btn-primary">
                {loading ? 'Generating Hash...' : 'Generate Secret Key'}
              </button>
            </div>
          </div>
        ) : (
          <div>
            <div
              style={{
                background: 'rgba(16, 185, 129, 0.15)',
                border: '1px solid #10b981',
                padding: '1rem',
                borderRadius: '8px',
                marginBottom: '1.5rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                <Check size={18} color="#34d399" />
                <span style={{ fontWeight: 600, color: '#34d399', fontSize: '0.9rem' }}>
                  Credential Successfully Issued & Hashed
                </span>
              </div>
              <p style={{ fontSize: '0.78rem', color: '#a7f3d0' }}>
                Copy your secret key now. You will not be able to see it again after closing this window.
              </p>
            </div>

            <div style={{ marginBottom: '1.5rem' }}>
              <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--color-text-muted)', marginBottom: '0.4rem', textTransform: 'uppercase', fontWeight: 600 }}>
                Plaintext Secret API Key (`aiiam_*`)
              </label>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <input
                  type="text"
                  readOnly
                  value={issuedKey.plaintext_key}
                  className="font-mono"
                  style={{
                    flex: 1,
                    padding: '0.75rem',
                    borderRadius: '8px',
                    background: '#060b19',
                    border: '1px solid var(--color-border-accent)',
                    color: '#00f5ff',
                    fontSize: '0.85rem',
                  }}
                />
                <button
                  onClick={handleCopy}
                  className="btn-primary"
                  style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}
                >
                  {copied ? <Check size={16} /> : <Copy size={16} />}
                  <span>{copied ? 'Copied!' : 'Copy'}</span>
                </button>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', background: 'rgba(6, 11, 25, 0.7)', padding: '1rem', borderRadius: '8px', marginBottom: '1.75rem' }}>
              <div>
                <span style={{ fontSize: '0.7rem', color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>Key ID</span>
                <div className="font-mono" style={{ fontSize: '0.85rem', color: '#fff', fontWeight: 600 }}>{issuedKey.key_id}</div>
              </div>
              <div>
                <span style={{ fontSize: '0.7rem', color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>Key Hint</span>
                <div className="font-mono" style={{ fontSize: '0.85rem', color: '#fff', fontWeight: 600 }}>••••{issuedKey.key_hint}</div>
              </div>
            </div>

            <button onClick={onClose} className="btn-secondary" style={{ width: '100%' }}>
              I have copied the key securely
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
