"use client";

/**
 * Report detail — summary, findings, and exports.
 *
 * Exports are downloaded through the API with the Supabase bearer token
 * (plain links would be unauthenticated) and saved via a temporary blob URL.
 */

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import EmptyState from "@/components/EmptyState";
import ErrorAlert from "@/components/ErrorAlert";
import FindingsList from "@/components/FindingsList";
import Loading from "@/components/Loading";
import { ApiError } from "@/lib/api-client";
import { formatDateTime } from "@/lib/format";
import { createClient } from "@/lib/supabase/client";
import type { ScanEnvelope, Severity } from "@/lib/types";
import { useApiClient } from "@/lib/useApiClient";

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

type ExportFormat = "markdown" | "sarif" | "json";

export default function ReportClient({ reportId }: { reportId: string }) {
  const { api, initializing, error: hookError } = useApiClient();

  const [envelope, setEnvelope] = useState<ScanEnvelope | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [exporting, setExporting] = useState<ExportFormat | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);

  useEffect(() => {
    if (!api) return;
    let cancelled = false;
    (async () => {
      try {
        const data = await api.getReportEnvelope(reportId);
        if (!cancelled) setEnvelope(data);
      } catch (err) {
        if (cancelled) return;
        if (err instanceof ApiError && err.status === 404) {
          setNotFound(true);
        } else {
          setLoadError("Could not load this report. Please refresh to try again.");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [api, reportId]);

  const handleExport = useCallback(
    async (format: ExportFormat) => {
      if (!api) return;
      setExportError(null);
      setExporting(format);
      try {
        const supabase = createClient();
        const {
          data: { session },
        } = await supabase.auth.getSession();
        if (!session) {
          throw new ApiError(401, "Your session has expired.");
        }
        const url = api.getReportExportUrl(reportId, format);
        const response = await fetch(url, {
          headers: { Authorization: `Bearer ${session.access_token}` },
          cache: "no-store",
        });
        if (!response.ok) {
          throw new ApiError(response.status, "The export could not be generated.");
        }
        const blob = await response.blob();
        const objectUrl = URL.createObjectURL(blob);
        const anchor = document.createElement("a");
        anchor.href = objectUrl;
        anchor.download = `${reportId}.${format === "markdown" ? "md" : format}`;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        URL.revokeObjectURL(objectUrl);
      } catch {
        setExportError(
          "The export could not be downloaded. Please try again in a moment."
        );
      } finally {
        setExporting(null);
      }
    },
    [api, reportId]
  );

  if (initializing) return <Loading label="Checking your session…" />;

  if (notFound) {
    return (
      <div className="container">
        <div className="empty-state">
          <h1>Report not found</h1>
          <p className="mb-6">This report doesn&apos;t exist or you don&apos;t have access to it.</p>
          <Link href="/dashboard" className="btn btn-primary">
            Back to dashboard
          </Link>
        </div>
      </div>
    );
  }

  if (!envelope) {
    return (
      <div className="container">
        {(loadError || hookError) && <ErrorAlert message={loadError ?? hookError ?? ""} />}
        {!loadError && !hookError && <Loading label="Loading report…" />}
      </div>
    );
  }

  const findings = envelope.scan.findings ?? [];
  const bySeverity = envelope.scan.summary?.by_severity ?? {};

  return (
    <div className="container">
      <div className="page-header">
        <p className="text-sm text-dim mb-2">
          <Link href="/dashboard">Dashboard</Link>
          {envelope.report_id && (
            <>
              {" / "}
              <span>Report</span>
            </>
          )}
        </p>
        <h1>Scan report</h1>
        <p className="text-sm text-muted mt-2">
          <span className="font-mono">{envelope.report_id.slice(0, 8)}…</span>
          {envelope.created_at && <> · generated {formatDateTime(envelope.created_at)}</>}
          {envelope.scan.scan_profile && <> · profile: {envelope.scan.scan_profile}</>}
        </p>
      </div>

      {(hookError || exportError) && (
        <div className="mb-4">
          <ErrorAlert message={exportError ?? hookError ?? ""} />
        </div>
      )}

      {/* ── Summary ───────────────────────────────────────────────────── */}
      <section className="card mb-6">
        <h2 style={{ marginBottom: "var(--space-4)" }}>Summary</h2>
        <div className="stat-grid">
          <div className="stat-card">
            <div className="stat-value">{envelope.scan.summary?.total_findings ?? findings.length}</div>
            <div className="stat-label">Total findings</div>
          </div>
          {SEVERITY_ORDER.map((severity) => (
            <div className="stat-card" key={severity}>
              <div className="stat-value">{bySeverity[severity] ?? 0}</div>
              <div className="stat-label">{severity.charAt(0) + severity.slice(1).toLowerCase()}</div>
            </div>
          ))}
        </div>
      </section>

      {/* ── Export ────────────────────────────────────────────────────── */}
      <section className="card mb-6">
        <h2 style={{ marginBottom: "var(--space-4)" }}>Export</h2>
        <div className="flex items-center gap-4 flex-wrap">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => handleExport("markdown")}
            disabled={exporting !== null}
          >
            {exporting === "markdown" ? "Preparing…" : "Markdown (.md)"}
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => handleExport("sarif")}
            disabled={exporting !== null}
          >
            {exporting === "sarif" ? "Preparing…" : "SARIF (.sarif)"}
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => handleExport("json")}
            disabled={exporting !== null}
          >
            {exporting === "json" ? "Preparing…" : "JSON (.json)"}
          </button>
        </div>
      </section>

      {/* ── Findings ──────────────────────────────────────────────────── */}
      <section>
        <h2 style={{ marginBottom: "var(--space-4)" }}>
          Findings ({findings.length})
        </h2>
        <FindingsList findings={findings} />
      </section>

      {findings.length > 0 && (
        <p className="text-xs text-dim mt-6">
          Findings marked <strong>Suspected (unconfirmed)</strong> or{" "}
          <strong>Unverified</strong> are candidate issues that have not been
          confirmed by the verification engine. Treat them as leads, not
          confirmed vulnerabilities.
        </p>
      )}
    </div>
  );
}
