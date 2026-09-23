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
            23 slices shipped · live-verified, not a design doc
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

        {/* Deliberately not using the shared .btn-primary/.btn-secondary
            classes here — those were repointed to the dashboard's red
            reskin, and this hero (unlike ProductPreview, which is
            meant to mirror the real dashboard) keeps its original
            cyan-on-dark look, independent of that change. */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
          <Link
            to="/login"
            className="flex items-center gap-2 px-6 py-3 text-base font-semibold rounded-lg"
            style={{
              background: 'linear-gradient(90deg, #00f5ff 0%, #0284c7 100%)',
              color: '#060b19',
              boxShadow: '0 0 15px rgba(0, 245, 255, 0.3)',
            }}
          >
            <span>Sign in to Dashboard</span>
            <ArrowRight size={18} />
          </Link>
          <a
            href="#architecture"
            className="px-6 py-3 text-base font-medium rounded-lg"
            style={{
              background: 'rgba(255, 255, 255, 0.06)',
              color: '#f8fafc',
              border: '1px solid rgba(0, 245, 255, 0.18)',
            }}
          >
            View Architecture
          </a>
        </div>

        <Link to="/trial" className="inline-block mt-6 text-sm font-medium" style={{ color: '#7dd3fc' }}>
          Start your free trial org →
        </Link>
      </div>
    </section>
  );
}
