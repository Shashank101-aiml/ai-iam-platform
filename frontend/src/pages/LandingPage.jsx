import React, { useEffect } from 'react';
import Hero from '../components/landing/Hero.jsx';
import FeatureGrid from '../components/landing/FeatureGrid.jsx';
import TrustBar from '../components/landing/TrustBar.jsx';
import ArchitectureSection from '../components/landing/ArchitectureSection.jsx';
import ProductPreview from '../components/landing/ProductPreview.jsx';
import Footer from '../components/landing/Footer.jsx';

export default function LandingPage() {
  // Landing/login share the light marketing surface; the dashboard
  // keeps the original dark gradient body.
  useEffect(() => {
    document.body.classList.add('on-light-surface');
    return () => document.body.classList.remove('on-light-surface');
  }, []);

  return (
    <div>
      <Hero />
      <TrustBar />
      <FeatureGrid />
      <ArchitectureSection />
      <ProductPreview />
      <Footer />
    </div>
  );
}
