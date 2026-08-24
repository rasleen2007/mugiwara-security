"use client";

/**
 * Scan detail — live job status.
 *
 * Polls GET /api/jobs/:id every few seconds until a terminal status is
 * reached. Queued jobs can be cancelled. When the job completes, the newest
 * report for the project (created after the job started) is linked.
 */

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import EmptyState from "@/components/EmptyState";
import ErrorAlert from "@/components/ErrorAlert";
import JobStatusBadge from "@/components/JobStatusBadge";
import Loading from "@/components/Loading";
import { ApiError } from "@/lib/api-client";
import { formatDateTime, truncate } from "@/lib/format";
import { TERMINAL_JOB_STATUSES, type Job, type Report } from "@/lib/types";
import { useApiClient } from "@/lib/useApiClient";

const POLL_INTERVAL_MS = 4000;

export default function ScanClient({ jobId }: { jobId: string }) {
  const { api, initializing, error: hookError } = useApiClient();

  const [job, setJob] = useState<Job | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [reportLink, setReportLink] = useState<Report | null>(null);

  // Keep polling loop free of stale closures without re-creating timers.
  const apiRef = useRef(api);
  apiRef.current = api;

  useEffect(() => {
    if (!api) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    async function poll() {
      const client = apiRef.current;
      if (!client || cancelled) return;
      try {
        const current = await client.getJob(jobId);
        if (cancelled) return;
        setJob(current);
        setLoadError(null);

        if (!TERMINAL_JOB_STATUSES.has(current.status)) {
          timer = setTimeout(poll, POLL_INTERVAL_MS);
        }
      } catch (err) {
        if (cancelled) return;
        if (err instanceof ApiError && err.status === 404) {
          setNotFound(true);
          return;
        }
        if (err instanceof ApiError && err.status === 401) {
          setLoadError("Your session has expired.");
          return;
        }
        // Transient failures keep polling; persistent ones surface an error
        // banner but the loop continues so recovery is automatic.
        setLoadError(
          err instanceof TypeError
            ? "Network error while checking scan progress — retrying…"
            : "Could not check scan progress — retrying…"
        );
        timer = setTimeout(poll, POLL_INTERVAL_MS * 2);
      }
    }

    void poll();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [api, jobId]);

  /** When the job completes, find the matching report (newest for project). */
  useEffect(() => {
    if (!api || job?.status !== "completed") return;
    let cancelled = false;
    (async () => {
      try {
        const reports = await api.listReports({
          projectId: job.project_id ?? undefined,
          limit: 20,
        });
        if (cancelled) return;
        const startedAt = new Date(job.started_at ?? job.created_at).getTime();
        const candidates = reports.filter(
          (r) => r.project_id === job.project_id &&
            new Date(r.created_at).getTime() >= startedAt - 1000
        );
        candidates.sort(
          (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
        );
        setReportLink(candidates[0] ?? null);
      } catch {
        // Non-fatal: user can still reach the report from the project page.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [api, job]);

  const handleCancel = useCallback(async () => {
    if (!api || !job) return;
    setActionError(null);
    setCancelling(true);
    try {
      await api.cancelJob(job.id);
      setJob({ ...job, status: "cancelled" });
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setActionError("This scan can no longer be cancelled — it already started.");
      } else {
        setActionError("The scan could not be cancelled. Please try again.");
      }
    } finally {
      setCancelling(false);
    }
  }, [api, job]);

  if (initializing) return <Loading label="Checking your session…" />;

  if (notFound) {
    return (
      <div className="container">
        <div className="empty-state">
          <h1>Scan not found</h1>
          <p className="mb-6">This scan doesn&apos;t exist or you don&apos;t have access to it.</p>
          <Link href="/dashboard" className="btn btn-primary">
            Back to dashboard
          </Link>
        </div>
      </div>
    );
  }

  if (!job) {
    return (
      <div className="container">
        {(loadError || hookError) && <ErrorAlert message={loadError ?? hookError ?? ""} />}
        {!loadError && !hookError && <Loading label="Loading scan…" />}
      </div>
    );
  }

  const isRunning = !TERMINAL_JOB_STATUSES.has(job.status);

  return (
    <div className="container">
      <div className="page-header">
        <p className="text-sm text-dim mb-2">
          <Link href="/dashboard">Dashboard</Link>
          {job.project_id && (
            <>
              {" / "}
              <Link href={`/projects/${job.project_id}`}>Project</Link>
            </>
          )}
        </p>
        <h1>Scan {job.id.slice(0, 8)}…</h1>
        <p className="text-sm text-muted mt-2 flex items-center gap-2">
          <JobStatusBadge status={job.status} />
          <span>· profile: {job.scan_profile}</span>
          <span>· created {formatDateTime(job.created_at)}</span>
        </p>
      </div>

      {(loadError || actionError || hookError) && (
        <div className="mb-4">
          <ErrorAlert message={actionError ?? loadError ?? hookError ?? ""} />
        </div>
      )}

      {/* ── Status card ───────────────────────────────────────────────── */}
      <section className="card mb-6">
        {isRunning ? (
          <div className="loading-container" style={{ padding: "var(--space-4)" }}>
            <span className="spinner" aria-hidden="true" />
            <span>
              {job.status === "queued"
                ? "Waiting in the queue…"
                : "Scanning in progress — this page updates automatically."}
            </span>
          </div>
        ) : job.status === "completed" ? (
          reportLink ? (
            <div className="alert alert-success">
              Scan completed.{" "}
              <Link href={`/reports/${reportLink.report_id}`} className="font-medium">
                Open the report →
              </Link>
            </div>
          ) : (
            <div className="alert alert-info">
              Scan completed. The report will appear on the project page
              momentarily.{" "}
              {job.project_id && (
                <Link href={`/projects/${job.project_id}`} className="font-medium">
                  Go to project →
                </Link>
              )}
            </div>
          )
        ) : job.status === "failed" ? (
          <div className="alert alert-error">
            This scan failed. {job.error ? `Reason: ${truncate(job.error, 200)}` : "No additional information is available."} You can start a new scan from the project page.
          </div>
        ) : (
          <div className="alert alert-info">This scan was cancelled.</div>
        )}

        <dl className="meta-grid mt-6">
          <div className="meta-item">
            <dt>Status</dt>
            <dd><JobStatusBadge status={job.status} /></dd>
          </div>
          <div className="meta-item">
            <dt>Attempts</dt>
            <dd>{job.attempts}</dd>
          </div>
          <div className="meta-item">
            <dt>Started</dt>
            <dd>{formatDateTime(job.started_at)}</dd>
          </div>
          <div className="meta-item">
            <dt>Completed</dt>
            <dd>{formatDateTime(job.completed_at)}</dd>
          </div>
        </dl>

        {isRunning && job.status === "queued" && (
          <div className="mt-6">
            <button
              type="button"
              className="btn btn-danger"
              onClick={handleCancel}
              disabled={cancelling}
            >
              {cancelling ? "Cancelling…" : "Cancel scan"}
            </button>
          </div>
        )}
      </section>

      {/* ── Progress phases ───────────────────────────────────────────── */}
      <section className="card">
        <h2 style={{ marginBottom: "var(--space-4)" }}>Progress</h2>
        {job.phases.length === 0 ? (
          <EmptyState title="No activity yet">
            <p>Phase updates appear here once the worker picks up the scan.</p>
          </EmptyState>
        ) : (
          <ul style={{ listStyle: "none" }}>
            {job.phases.map((phase, index) => (
              <li key={`${index}-${phase}`} className="font-mono text-sm text-muted py-1">
                {phase}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
