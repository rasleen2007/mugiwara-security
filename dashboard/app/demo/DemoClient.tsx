"use client";

/**
 * Demo / Guest mode — a public, STATIC preview of a Mugiwara security report.
 *
 * NO AUTHENTICATION IS REQUIRED, and NO backend/API calls are made. All data
 * comes from the static sample dataset in lib/demo-data.ts. This lets
 * visitors exploring the product see the report UX without signing up.
 */

import Link from "next/link";
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

export default function DemoClient() {
  const bySeverity = DEMO_ENVELOPE.scan.summary?.by_severity ?? {};
  const byStatus = DEMO_ENVELOPE.scan.summary?.by_status ?? {};

  return (
    <div className="container">
      {/* ── Demo banner ───────────────────────────────────────────────── */}
      <div className="demo-banner" role="note">
        <div>
          <strong>Demo Mode</strong> — you&apos;re viewing a sample report with
          pre-loaded example data. No account or real scan is used.
        </div>
        <Link href="/signup" className="btn btn-cta btn-sm">
          Create an account
        </Link>
      </div>

      {/* ── Page header ──────────────────────────────────────────────── */}
      <div className="page-header">
        <p className="text-sm text-dim mb-2">
          <Link href="/">Mugiwara Security</Link> / Demo
        </p>
        <h1>Sample scan report</h1>
        <p className="text-sm text-muted mt-2">
          Project: <span className="font-mono">{DEMO_PROJECT_NAME}</span>
          {" · "}generated {formatDateTime(DEMO_REPORT.created_at)}
          {" · "}profile: standard
        </p>
      </div>

      {/* ── Summary ───────────────────────────────────────────────────── */}
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

      {/* ── Sample project ───────────────────────────────────────────── */}
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

      {/* ── Findings ──────────────────────────────────────────────────── */}
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

      {/* ── Account CTA ───────────────────────────────────────────────── */}
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
    </div>
  );
}
