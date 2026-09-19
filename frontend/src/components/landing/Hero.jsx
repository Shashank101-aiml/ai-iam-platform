import React from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight, ShieldCheck } from 'lucide-react';
import heroImage from '../../assets/hero-office.webp';

export default function Hero() {
  return (
    <section
      className="relative flex items-center min-h-[92vh] bg-cover bg-center"
      style={{ backgroundImage: `url(${heroImage})` }}
    >
      {/* Dark gradient overlay for text legibility over the photo — the
          rest of the landing page is a light surface, this is the one
          section that deliberately isn't. */}
      <div className="absolute inset-0 bg-gradient-to-b from-black/80 via-black/60 to-surface-50" />

      <div className="relative max-w-5xl mx-auto px-6 py-32 text-center">
        <div className="inline-flex items-center gap-2 bg-white/10 border border-white/20 backdrop-blur-sm rounded-full px-4 py-1.5 mb-8">
          <ShieldCheck size={14} className="text-cyan-glow" />
          <span className="text-xs font-semibold text-white/90 uppercase tracking-wide">
            16 slices shipped · live-verified, not a design doc
          </span>
        </div>

        <h1 className="font-outfit text-4xl sm:text-5xl md:text-6xl font-bold text-white leading-[1.08] mb-6">
          Identity &amp; access management,{' '}
          <span className="bg-clip-text text-transparent bg-gradient-to-r from-cyan-glow to-brand-600">
            built for autonomous AI agents.
          </span>
        </h1>

        <p className="text-lg text-slate-200 max-w-2xl mx-auto mb-10 leading-relaxed">
          Server-verified delegation, pre-execution OPA policy, a tamper-evident
          hash-chained audit log, and provenance-aware authorization — so an
          agent can never inherit more privilege than it was ever given, and
          every action it takes is provably accountable.
        </p>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
          <Link to="/login" className="btn-primary flex items-center gap-2 px-6 py-3 text-base">
            <span>Sign in to Dashboard</span>
            <ArrowRight size={18} />
          </Link>
          <a href="#architecture" className="btn-secondary px-6 py-3 text-base">
            View Architecture
          </a>
        </div>
      </div>
    </section>
  );
}
