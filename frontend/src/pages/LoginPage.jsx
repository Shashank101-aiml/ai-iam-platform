import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { ShieldCheck, AlertOctagon, LogIn } from 'lucide-react';
import { apiService } from '../services/api.js';

const TOKEN_KEY = 'aiiam_operator_token';

export default function LoginPage() {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Login/landing share the light marketing surface; the dashboard
  // keeps the original dark gradient body — toggled via a class rather
  // than duplicating index.css's body rule per-page.
  useEffect(() => {
    document.body.classList.add('on-light-surface');
    return () => document.body.classList.remove('on-light-surface');
  }, []);

  // Already logged in? Don't show the login form again.
  useEffect(() => {
    if (localStorage.getItem(TOKEN_KEY)) {
      navigate('/dashboard', { replace: true });
    }
  }, [navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await apiService.login(email, password);
      navigate('/dashboard', { replace: true });
    } catch (err) {
      setError(err.message || 'Login failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <Link to="/" className="flex items-center justify-center gap-2 mb-8">
          <div className="bg-gradient-to-br from-cyan-glow to-sapphire p-2 rounded-[10px] shadow-[0_0_16px_rgba(0,245,255,0.4)]">
            <ShieldCheck size={22} className="text-bg-deep" strokeWidth={2.5} />
          </div>
          <span className="font-outfit text-lg font-bold text-ink-900">
            AI-IAM <span className="text-brand-600">PLATFORM</span>
          </span>
        </Link>

        <div className="glass-panel p-8" style={{ background: 'rgba(10, 17, 40, 0.95)' }}>
          <h1 className="font-outfit text-2xl font-bold text-white mb-1">Operator sign-in</h1>
          <p className="text-sm text-text-muted mb-6">
            Sign in to manage agents, delegation chains, and the audit ledger.
          </p>

          {error && (
            <div className="glass-panel flex items-start gap-3 p-4 mb-5 border border-rose" role="alert">
              <AlertOctagon size={20} className="text-rose shrink-0 mt-0.5" />
              <div className="font-mono text-sm" style={{ color: '#fb7185' }}>{error}</div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <div>
              <label htmlFor="email" className="block text-sm font-semibold text-slate-200 mb-1.5">
                Email
              </label>
              <input
                id="email"
                type="email"
                required
                autoComplete="username"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="admin@acmecorp.ai"
                className="w-full p-3 rounded-lg bg-bg-deep border border-border-glass text-white text-sm outline-none focus:border-cyan-glow"
              />
            </div>
            <div>
              <label htmlFor="password" className="block text-sm font-semibold text-slate-200 mb-1.5">
                Password
              </label>
              <input
                id="password"
                type="password"
                required
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full p-3 rounded-lg bg-bg-deep border border-border-glass text-white text-sm outline-none focus:border-cyan-glow"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary flex items-center justify-center gap-2 mt-2"
            >
              <LogIn size={16} />
              <span>{loading ? 'Signing in…' : 'Sign in'}</span>
            </button>
          </form>
        </div>

        <p className="text-center text-sm text-ink-600 mt-6">
          <Link to="/" className="text-brand-600 hover:underline">← Back to overview</Link>
        </p>
      </div>
    </div>
  );
}
