"use client";

import { useEffect } from "react";
import Link from "next/link";

/** Scroll to the hash target on mount and on hash change. */
function useHashScroll() {
  useEffect(() => {
    function scrollToHash() {
      const hash = window.location.hash;
      if (!hash) return;
      const el = document.getElementById(hash.slice(1));
      if (el) el.scrollIntoView({ behavior: "smooth" });
    }
    scrollToHash();
    window.addEventListener("hashchange", scrollToHash);
    return () => window.removeEventListener("hashchange", scrollToHash);
  }, []);
}

const FEATURES = [
  {
    icon: "🤖",
    title: "Autonomous AI Discovery",
    desc: "AI security agents map your app\u2019s attack surface and flag suspected vulnerabilities with CWE mapping.",
  },
  {
    icon: "🎯",
    title: "Dynamic Sandbox Verification",
    desc: "Suspected issues are actively probed in an isolated, ephemeral sandbox so only real risks are reported.",
  },
  {
    icon: "✅",
    title: "Honest, Evidence-Backed Outcomes",
    desc: "Every claim is classified VERIFIED, FALSE_POSITIVE, or UNVERIFIED \u2014 never over-stated, with proof attached.",
  },
  {
    icon: "🩹",
    title: "Sandbox-Proven Remediation",
    desc: "AI patches are applied to an isolated copy and re-tested so a fix is proven before you touch your code.",
  },
  {
    icon: "📊",
    title: "Severity-First Reports",
    desc: "Review findings by severity with full context, reachable evidence, and a clear actionable summary.",
  },
  {
    icon: "🔐",
    title: "Secure Authenticated Workspace",
    desc: "Keep projects, scans, and reports inside your personal, access-controlled account in the cloud.",
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
    desc: "AI agents recon the app, discover suspected issues, then verify each in an isolated sandbox.",
  },
  {
    num: "03",
    title: "Analyze",
    desc: "Review verified findings by severity, with evidence and clear remediation guidance.",
  },
  {
    num: "04",
    title: "Report",
    desc: "Export structured security reports and apply sandbox-proven fixes with confidence.",
  },
];

export default function LandingPage() {
  useHashScroll();

  return (
    <div className="landing">
      {/* Hero */}
      <section className="landing-hero">
        <div className="container">
          <div className="landing-hero-badge">Autonomous Security Testing Platform</div>
          <h1 className="landing-hero-title">
            Find real vulnerabilities
            <br />
            without the false alarms.
          </h1>
          <p className="landing-hero-subtitle">
            Mugiwara Security combines AI-powered vulnerability discovery with
            dynamic sandbox verification, so every reported issue is actively
            tested and backed by evidence &mdash; not just flagged by heuristics.
          </p>
          <div className="landing-hero-actions">
            <Link href="/demo" className="btn btn-cta btn-lg">
              Try the demo
            </Link>
            <Link href="/signup" className="btn btn-secondary btn-lg">
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
            Mugiwara Security is an autonomous, AI-powered application security
            testing platform. Upload your project or source archive and it maps
            the attack surface, discovers suspected vulnerabilities, and &mdash;
            crucially &mdash; actively verifies each one by running a safe proof-of-concept
            probe in a secure, ephemeral sandbox. The result is an honest,
            severity-ranked report where every claim is either verified with
            evidence or explicitly labeled as not proven, plus AI-generated
            fixes that are sandbox-tested before you apply them.
          </p>
          <div className="landing-about-grid">
            <div className="landing-about-item">
              <div className="landing-about-icon">📁</div>
              <div>
                <h4>Upload</h4>
                <p>Submit a ZIP archive of your source code via a secure, signed upload.</p>
              </div>
            </div>
            <div className="landing-about-item">
              <div className="landing-about-icon">🧭</div>
              <div>
                <h4>Recon</h4>
                <p>
                  AI agents map the tech stack and attack surface, extracting
                  routes and frameworks to focus the scan.
                </p>
              </div>
            </div>
            <div className="landing-about-item">
              <div className="landing-about-icon">🔎</div>
              <div>
                <h4>Discover</h4>
                <p>
                  Detect suspected vulnerabilities with severity and CWE mapping
                  so you know what to prioritize.
                </p>
              </div>
            </div>
            <div className="landing-about-item">
              <div className="landing-about-icon">🧪</div>
              <div>
                <h4>Verify</h4>
                <p>
                  High-risk candidates are actively tested in an isolated sandbox
                  with safe, evidence-backed proof-of-concept probes.
                </p>
              </div>
            </div>
            <div className="landing-about-item">
              <div className="landing-about-icon">🩹</div>
              <div>
                <h4>Remediate</h4>
                <p>
                  Get AI-generated patches that are applied to an isolated copy
                  and re-tested to prove the fix works.
                </p>
              </div>
            </div>
            <div className="landing-about-item">
              <div className="landing-about-icon">📑</div>
              <div>
                <h4>Report</h4>
                <p>
                  Access structured reports with severity breakdowns, evidence,
                  and actionable remediation guidance.
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
            <h2>Verified findings, proven fixes &mdash; not speculation.</h2>
            <p>
              Mugiwara Security is built on an honest verification philosophy:
              every reported vulnerability is either dynamically tested and
              confirmed with evidence, or explicitly classified as unverified.
              AI-generated remediations are applied to an isolated copy and
              re-tested before you ever change your working code, so you can act
              on results with real confidence.
            </p>
          </div>
        </div>
      </section>

      {/* Final CTA */}
      <section className="landing-section landing-cta-section">
        <div className="container" style={{ textAlign: "center" }}>
          <h2 className="landing-cta-title">Ready to scan your project?</h2>
          <p className="landing-cta-sub">
            Explore a sample report right now, or create a free account and run
            your first scan in minutes.
          </p>
          <div className="landing-hero-actions">
            <Link href="/demo" className="btn btn-cta btn-lg">
              Try the demo
            </Link>
            <Link href="/signup" className="btn btn-secondary btn-lg">
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
