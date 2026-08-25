"use client";

import Link from "next/link";

const FEATURES = [
  {
    icon: "🔍",
    title: "Automated Security Scanning",
    desc: "Analyze uploaded projects for security vulnerabilities using multiple detection techniques.",
  },
  {
    icon: "🚨",
    title: "Severity-Based Findings",
    desc: "Quickly identify critical and high-risk issues so you can prioritize what matters most.",
  },
  {
    icon: "🛠️",
    title: "Remediation Guidance",
    desc: "Understand how detected issues can be addressed with actionable recommendations.",
  },
  {
    icon: "📊",
    title: "Security Reports",
    desc: "Review scan results in a structured report with severity breakdowns and evidence.",
  },
  {
    icon: "☁️",
    title: "Cloud-Based Processing",
    desc: "Submit scans and let the cloud worker process them while you focus on development.",
  },
  {
    icon: "🔐",
    title: "Secure Authenticated Workspace",
    desc: "Keep projects, scans, and reports inside your personal account with full access control.",
  },
];

const STEPS = [
  {
    num: "01",
    title: "Upload",
    desc: "Upload your project or source code archive through a secure, signed URL.",
  },
  {
    num: "02",
    title: "Scan",
    desc: "Mugiwara's security engine analyzes your project for potential vulnerabilities.",
  },
  {
    num: "03",
    title: "Analyze",
    desc: "Review detected vulnerabilities organized by severity and type.",
  },
  {
    num: "04",
    title: "Report",
    desc: "View the generated security report with findings and remediation guidance.",
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
            Find vulnerabilities
            <br />
            before attackers do.
          </h1>
          <p className="landing-hero-subtitle">
            Mugiwara Security is a cloud security scanning platform that helps
            developers discover vulnerabilities in their projects, understand
            security findings, and generate actionable reports.
          </p>
          <div className="landing-hero-actions">
            <Link href="/signup" className="btn btn-cta btn-lg">
              Get Started
            </Link>
            <Link href="/login" className="btn btn-secondary btn-lg">
              Log In
            </Link>
          </div>
        </div>
        <div className="landing-hero-glow" aria-hidden="true" />
      </section>

      {/* About / What is Mugiwara */}
      <section id="about" className="landing-section landing-about">
        <div className="container">
          <div className="landing-section-eyebrow">About</div>
          <h2 className="landing-section-title">
            What is Mugiwara Security?
          </h2>
          <p className="landing-about-lead">
            Mugiwara Security allows developers to upload a project, run
            automated security scans, and review findings &mdash; all from a
            single platform. It detects potentially dangerous code patterns and
            vulnerabilities, helps you understand remediation steps, and
            generates structured security reports.
          </p>
          <div className="landing-about-grid">
            <div className="landing-about-item">
              <div className="landing-about-icon">📁</div>
              <div>
                <h4>Upload</h4>
                <p>Submit a ZIP archive of your source code or project files.</p>
              </div>
            </div>
            <div className="landing-about-item">
              <div className="landing-about-icon">🔎</div>
              <div>
                <h4>Scan</h4>
                <p>
                  Run automated security scans across multiple detection
                  techniques.
                </p>
              </div>
            </div>
            <div className="landing-about-item">
              <div className="landing-about-icon">⚠️</div>
              <div>
                <h4>Detect</h4>
                <p>
                  Identify potentially dangerous code patterns and
                  vulnerabilities.
                </p>
              </div>
            </div>
            <div className="landing-about-item">
              <div className="landing-about-icon">📋</div>
              <div>
                <h4>Review</h4>
                <p>
                  Examine findings by severity with full context and evidence.
                </p>
              </div>
            </div>
            <div className="landing-about-item">
              <div className="landing-about-icon">💡</div>
              <div>
                <h4>Remediate</h4>
                <p>
                  Understand remediation recommendations for each detected
                  issue.
                </p>
              </div>
            </div>
            <div className="landing-about-item">
              <div className="landing-about-icon">📑</div>
              <div>
                <h4>Report</h4>
                <p>
                  Generate and access structured security reports for your
                  projects.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="landing-section landing-features-section">
        <div className="container">
          <div className="landing-section-eyebrow">Capabilities</div>
          <h2 className="landing-section-title">Key Features</h2>
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

      {/* How it works */}
      <section id="how-it-works" className="landing-section landing-how-section">
        <div className="container">
          <div className="landing-section-eyebrow">Workflow</div>
          <h2 className="landing-section-title">How it works</h2>
          <div className="landing-steps">
            {STEPS.map((s) => (
              <div key={s.num} className="landing-step">
                <div className="landing-step-num">{s.num}</div>
                <h3>{s.title}</h3>
                <p>{s.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Trust / Product */}
      <section className="landing-section landing-trust-section">
        <div className="container">
          <div className="landing-trust-card">
            <div className="landing-trust-icon">🛡️</div>
            <h2>From source code to actionable security findings.</h2>
            <p>
              Mugiwara Security is designed to make security testing easier to
              understand for developers. No need to manually inspect every
              potential vulnerability &mdash; upload your project, run a scan,
              and get clear, structured results with remediation guidance.
            </p>
          </div>
        </div>
      </section>

      {/* Final CTA */}
      <section className="landing-section landing-cta-section">
        <div className="container" style={{ textAlign: "center" }}>
          <h2 className="landing-cta-title">Ready to scan your project?</h2>
          <p className="landing-cta-sub">
            Create a free account and run your first scan in minutes.
          </p>
          <div className="landing-hero-actions">
            <Link href="/signup" className="btn btn-cta btn-lg">
              Create Free Account
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
            &copy; {new Date().getFullYear()} Mugiwara Security. All rights
            reserved.
          </span>
        </div>
      </footer>
    </div>
  );
}
