import React from 'react';
import { Link } from 'react-router-dom';
import { ShieldCheck } from 'lucide-react';

const TAGS = [
  'RS256 JWT',
  'OPA / Rego',
  'SHA-256 audit chain',
  'Redis JTI revocation',
  'OAuth 2.1',
  'Provenance-aware policy',
];

export default function Footer() {
  return (
    <footer className="border-t border-surface-100">
      <div className="max-w-6xl mx-auto px-6 py-12 flex flex-col md:flex-row md:items-center md:justify-between gap-6">
        <div className="flex items-center gap-2">
          <div className="bg-gradient-to-br from-cyan-glow to-sapphire p-1.5 rounded-lg">
            <ShieldCheck size={18} className="text-bg-deep" strokeWidth={2.5} />
          </div>
          <span className="font-outfit font-bold text-ink-900">
            AI-IAM <span className="text-brand-600">PLATFORM</span>
          </span>
        </div>

        <div className="flex flex-wrap gap-2 justify-center">
          {TAGS.map((tag) => (
            <span key={tag} className="text-xs font-mono text-ink-600 bg-surface-100 px-2.5 py-1 rounded-full">
              {tag}
            </span>
          ))}
        </div>

        <Link to="/login" className="text-sm font-semibold text-brand-600 hover:underline">
          Operator sign-in →
        </Link>
      </div>
    </footer>
  );
}
