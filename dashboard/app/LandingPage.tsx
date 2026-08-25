"use client";

import Link from "next/link";

const FEATURES = [
  {
    icon: "🔍",
    title: "Automated Scanning",
    desc: "Upload your source code archives and run deep security scans powered by AI-driven analysis.",
  },
  {
    icon: "🛡️",
    title: "Vulnerability Detection",
    desc: "Identify critical, high, medium, and low-severity security issues across your codebase.",
  },
  {
    icon: "📊",
    title: "Detailed Reports",
    desc: "Get severity breakdowns, CWE mappings, CVSS scores, and remediation guidance for every finding.",
  },
  {
    icon: "⚡",
    title: "Multiple Scan Profiles",
    desc: "Choose from fast, standard, or deep scan profiles depending on your needs.",
  },
  {
    icon: "📁",
    title: "Project Organization",
    desc: "Organize scans by project, track history, and monitor your security posture over time.",
  },
  {
    icon: "📤",
    title: "Export Anywhere",
    desc: "Export reports as Markdown, SARIF, or JSON for integration with your existing workflows.",
  },
];

export default function LandingPage() {
  return (
    <div className="landing">
      {/* Hero */}
      <section className="landing-hero">
        <div className="container">
          <div className="landing-hero-badge">Security Scanning Platform</div>
          <h1 className="landing-hero-title">
            Find vulnerabilities<br />before attackers do.
          </h1>
          <p className="landing-hero-subtitle">
            Mugiwara Security is an AI-powered security scanning platform that
            analyzes your source code for vulnerabilities, maps findings to CWE
            standards, and gives you actionable remediation guidance.
          </p>
          <div className="landing-hero-actions">
            <Link href="/signup" className="btn btn-primary btn-lg">
              Get Started
            </Link>
            <Link href="/login" className="btn btn-secondary btn-lg">
              Log In
            </Link>
          </div>
        </div>
      </section>

      {/* How it works */}
      <section className="landing-section">
        <div className="container">
          <h2 className="landing-section-title">How it works</h2>
          <div className="landing-steps">
            <div className="landing-step">
              <div className="landing-step-num">1</div>
              <h3>Upload</h3>
              <p>Upload a ZIP archive of your source code to a secure, encrypted project.</p>
            </div>
            <div className="landing-step">
              <div className="landing-step-num">2</div>
              <h3>Scan</h3>
              <p>Our engine analyzes your code for security vulnerabilities using multiple detection techniques.</p>
            </div>
            <div className="landing-step">
              <div className="landing-step-num">3</div>
              <h3>Review</h3>
              <p>Explore findings with severity ratings, code locations, evidence, and remediation steps.</p>
            </div>
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="landing-section landing-section-alt">
        <div className="container">
          <h2 className="landing-section-title">Capabilities</h2>
          <div className="landing-features">
            {FEATURES.map((f) => (
              <div key={f.title} className="landing-feature-card">
                <div className="landing-feature-icon">{f.icon}</div>
                <h3>{f.title}</h3>
                <p>{f.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="landing-section landing-cta">
        <div className="container" style={{ textAlign: "center" }}>
          <h2>Ready to secure your code?</h2>
          <p className="landing-cta-sub">
            Create a free account and run your first scan in minutes.
          </p>
          <div className="landing-hero-actions">
            <Link href="/signup" className="btn btn-primary btn-lg">
              Create Account
            </Link>
            <Link href="/login" className="btn btn-secondary btn-lg">
              Log In
            </Link>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="landing-footer">
        <div className="container">
          <span className="landing-footer-brand">
            <span className="brand-mark">☠</span> Mugiwara Security
          </span>
          <span className="landing-footer-copy">
            &copy; {new Date().getFullYear()} Mugiwara Security. All rights reserved.
          </span>
        </div>
      </footer>
    </div>
  );
}
