"use client";

/**
 * Demo / Guest mode — a public "Try it" experience.
 *
 * NO AUTHENTICATION IS REQUIRED, and NO backend/API calls are made. A short,
 * client-side-only scan simulation runs first, then the EXISTING static sample
 * report (from lib/demo-data.ts) is revealed. This lets visitors experience
 * what scanning looks like without signing up, while clearly remaining
 * Demo Mode. Nothing is persisted and real users are never affected.
 */

import Link from "next/link";
import { useEffect, useState } from "react";
import FindingStatusBadge from "@/components/FindingStatusBadge";
import FindingsList from "@/components/FindingsList";
import JobStatusBadge from "@/components/JobStatusBadge";
import SeverityBadge from "@/components/SeverityBadge";
import { formatDateTime } from "@/lib/format";
import {
  DEMO_ENVELOPE,
  DEMO_JOBS,
  DEMO_PROJECT,
  DEMO_PROJECT_NAME,
  DEMO_REPORT,
} from "@/lib/demo-data";
import type { Severity } from "@/lib/types";

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

const SCAN_STEPS = [
  "Preparing sample project...",
  "Running security analysis...",
  "Analyzing findings...",
  "Generating report...",
  "Scan complete ✓",
];

const STEP_INTERVAL_MS = 900;

type ScanPhase = "idle" | "scanning" | "done";

export default function DemoClient() {
  const bySeverity = DEMO_ENVELOPE.scan.summary?.by_severity ?? {};
  const byStatus = DEMO_ENVELOPE.scan.summary?.by_status ?? {};

  const [phase, setPhase] = useState<ScanPhase>("idle");
  const [stepIndex, setStepIndex] = useState(0);

  const startScan = () => {
    setStepIndex(0);
    setPhase("scanning");
  };

  useEffect(() => {
    if (phase !== "scanning") return;
    setStepIndex(0);
    const timer = setInterval(() => {
      setStepIndex((i) => {
        if (i >= SCAN_STEPS.length - 1) {
          clearInterval(timer);
          setPhase("done");
          return i;
        }
        return i + 1;
      });
    }, STEP_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [phase]);

  return (
    <div className="container">
      {/* ── Demo banner ───────────────────────────────────────────────── */}
      <div className="demo-banner" role="note">
        <div>
          <strong>Demo Mode</strong> — you can try this without an account. No
          real scan is performed and no data is uploaded.
        </div>
        <Link href="/signup" className="btn btn-cta btn-sm">
          Create an account
        </Link>
      </div>

      {/* ── Try-it header ─────────────────────────────────────────────── */}
      <div className="page-header">
        <p className="text-sm text-dim mb-2">
          <Link href="/">Mugiwara Security</Link> / Demo
        </p>
        <h1>Try Mugiwara Security</h1>
        <p className="text-sm text-muted mt-2">
          Run a sample scan and see the report immediately — no account required.
        </p>
      </div>

      {/* ── Idle: start the demo scan ─────────────────────────────────── */}
      {phase === "idle" && (
        <section className="card mb-6 demo-scan-hero">
          <div className="demo-scan-hero-icon" aria-hidden="true">🛡️</div>
          <h2 style={{ marginBottom: "var(--space-2)" }}>
            Scan a sample project
          </h2>
          <p className="landing-cta-sub" style={{ marginBottom: "var(--space-5)" }}>
            No account required.
          </p>
          <button type="button" className="btn btn-cta btn-lg" onClick={startScan}>
            Scan a sample project {"\u2192"}
          </button>
          <p className="text-xs text-dim mt-4">
            Demo scan — uses a safe preloaded sample project.
          </p>
        </section>
      )}

      {/* ── Scanning: simulated progress ──────────────────────────────── */}
      {phase === "scanning" && (
        <section className="card mb-6">
          <h2 style={{ marginBottom: "var(--space-4)" }}>Scanning sample project…</h2>
          <p className="text-xs text-dim mb-4">
            Demo scan — uses a safe preloaded sample project.
          </p>
          <ul className="demo-scan-steps">
            {SCAN_STEPS.map((step, index) => (
              <li
                key={step}
                className={index < stepIndex ? "done" : index === stepIndex ? "active" : ""}
              >
                <span className="demo-scan-step-icon" aria-hidden="true">
                  {index < stepIndex ? "\u2713" : index === stepIndex ? <span className="spinner" /> : "\u00b7"}
                </span>
                <span>{step}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* ── Done: reveal the existing static report ───────────────────── */}
      {phase === "done" && (
        <>
          {/* Page header */}
          <div className="page-header">
            <p className="text-sm text-dim mb-2">
              <Link href="/">Mugiwara Security</Link> / Demo
            </p>
            <div className="flex items-center gap-3 flex-wrap">
              <h1>Sample scan report</h1>
              <span className="badge badge-status-verified">Demo report</span>
            </div>
            <p className="text-sm text-muted mt-2">
              Project: <span className="font-mono">{DEMO_PROJECT_NAME}</span>
              {" · "}generated {formatDateTime(DEMO_REPORT.created_at)}
              {" · "}profile: standard
            </p>
          </div>

          {/* Summary */}
          <section className="card mb-6">
            <h2 style={{ marginBottom: "var(--space-4)" }}>Summary</h2>
            <div className="stat-grid">
              <div className="stat-card">
                <div className="stat-value">{DEMO_ENVELOPE.scan.summary?.total_findings ?? 0}</div>
                <div className="stat-label">Total findings</div>
              </div>
              {SEVERITY_ORDER.map((severity) => (
                <div className="stat-card" key={severity}>
                  <div className="stat-value">{bySeverity[severity] ?? 0}</div>
                  <div className="stat-label">{severity.charAt(0) + severity.slice(1).toLowerCase()}</div>
                </div>
              ))}
            </div>
            <p className="text-xs text-dim mt-4">
              Sample verification statuses: {Object.entries(byStatus).map(([k, v]) => `${k}: ${v}`).join(" · ")}
            </p>
          </section>

          {/* Sample project */}
          <section className="card mb-6">
            <h2 style={{ marginBottom: "var(--space-2)" }}>Sample project</h2>
            <p className="text-sm text-muted mb-4">
              This is how a project, its scans, and its reports appear inside a
              real account.
            </p>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Created</th>
                    <th aria-label="Details" />
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>
                      <span className="font-mono">{DEMO_PROJECT.name}</span>
                    </td>
                    <td className="text-muted">{formatDateTime(DEMO_PROJECT.created_at)}</td>
                    <td>
                      <span className="badge badge-status-verified">Sample</span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            <h3 className="demo-subheading">Scans</h3>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Scan</th>
                    <th>Profile</th>
                    <th>Status</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {DEMO_JOBS.map((job) => (
                    <tr key={job.id}>
                      <td className="font-mono text-sm">{job.id.slice(0, 8)}…</td>
                      <td className="text-muted">{job.scan_profile}</td>
                      <td>
                        <JobStatusBadge status={job.status} />
                      </td>
                      <td className="text-muted">{formatDateTime(job.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <h3 className="demo-subheading">Report</h3>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Report</th>
                    <th>Target</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td className="font-mono text-sm">{DEMO_REPORT.report_id.slice(0, 8)}…</td>
                    <td className="text-muted">{DEMO_REPORT.target_label}</td>
                    <td className="text-muted">{formatDateTime(DEMO_REPORT.created_at)}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          {/* Findings */}
          <section className="card mb-6">
            <h2 style={{ marginBottom: "var(--space-4)" }}>
              Findings ({(DEMO_ENVELOPE.scan.findings ?? []).length})
            </h2>
            <div className="flex items-center gap-3 flex-wrap mb-4">
              <span className="text-sm text-muted">Legend:</span>
              <SeverityBadge severity="CRITICAL" />
              <SeverityBadge severity="HIGH" />
              <SeverityBadge severity="MEDIUM" />
              <SeverityBadge severity="LOW" />
              <FindingStatusBadge status="VERIFIED" />
              <FindingStatusBadge status="SUSPECTED" />
              <FindingStatusBadge status="FALSE_POSITIVE" />
            </div>
            <FindingsList findings={DEMO_ENVELOPE.scan.findings} />
            <p className="text-xs text-dim mt-6">
              Findings marked <strong>Suspected (unconfirmed)</strong> or{" "}
              <strong>Unverified</strong> are candidate issues that have not been
              confirmed by the verification engine. Treat them as leads, not
              confirmed vulnerabilities. This is sample data and does not come
              from a real scan.
            </p>
          </section>

          {/* Account CTA */}
          <section className="card mb-6" style={{ textAlign: "center" }}>
            <h2 style={{ marginBottom: "var(--space-2)" }}>
              Like what you see?
            </h2>
            <p className="landing-cta-sub">
              Create a free account to scan your own projects, verify findings in
              an isolated sandbox, and export structured reports.
            </p>
            <div className="landing-hero-actions" style={{ animation: "none" }}>
              <Link href="/signup" className="btn btn-cta btn-lg">
                Create free account
              </Link>
              <Link href="/login" className="btn btn-secondary btn-lg">
                Log in
              </Link>
            </div>
          </section>
        </>
      )}
    </div>
  );
}
