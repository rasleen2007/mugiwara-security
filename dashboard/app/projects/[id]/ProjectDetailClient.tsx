"use client";

/**
 * Project detail — upload a source ZIP, create a scan job, and review the
 * project's scans and reports.
 *
 * Upload flow (signed-URL pattern):
 *   1. POST /api/uploads/sign        → { path, upload_url } (short-lived)
 *   2. PUT the file to upload_url    → direct-to-storage, no auth header
 *   3. POST /api/jobs                → scan job referencing upload_path
 *
 * The signed URL is used immediately and never persisted or logged.
 */

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useRef, useState, type ChangeEvent, type FormEvent } from "react";
import EmptyState from "@/components/EmptyState";
import ErrorAlert from "@/components/ErrorAlert";
import JobStatusBadge from "@/components/JobStatusBadge";
import Loading from "@/components/Loading";
import { ApiError } from "@/lib/api-client";
import { formatBytes, formatDateTime } from "@/lib/format";
import type { Job, Project, Quota, Report } from "@/lib/types";
import { useApiClient } from "@/lib/useApiClient";

const SCAN_PROFILES = ["fast", "standard", "deep"] as const;
type ScanProfile = (typeof SCAN_PROFILES)[number];

/** SHA-256 hex digest of a blob; null when WebCrypto is unavailable. */
async function sha256Hex(file: File): Promise<string | null> {
  try {
    if (!globalThis.crypto?.subtle) return null;
    const digest = await globalThis.crypto.subtle.digest("SHA-256", await file.arrayBuffer());
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  } catch {
    return null;
  }
}

export default function ProjectDetailClient({ projectId }: { projectId: string }) {
  const router = useRouter();
  const { api, initializing, error: hookError } = useApiClient();

  const [project, setProject] = useState<Project | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [jobs, setJobs] = useState<Job[] | null>(null);
  const [reports, setReports] = useState<Report[] | null>(null);
  const [quota, setQuota] = useState<Quota | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  // Scan creation form state
  const [file, setFile] = useState<File | null>(null);
  const [profile, setProfile] = useState<ScanProfile>("standard");
  const [fileError, setFileError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadStage, setUploadStage] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!api) return;
    let cancelled = false;
    (async () => {
      try {
        const [projectData, jobList, reportList, quotaInfo] = await Promise.all([
          api.getProject(projectId),
          api.listJobs({ limit: 50 }),
          api.listReports({ projectId, limit: 20 }),
          api.getQuota(),
        ]);
        if (cancelled) return;
        setProject(projectData);
        setJobs(jobList.filter((j) => j.project_id === projectId));
        setReports(reportList);
        setQuota(quotaInfo);
      } catch (err) {
        if (cancelled) return;
        if (err instanceof ApiError && err.status === 404) {
          setNotFound(true);
        } else {
          setLoadError("Could not load this project. Please refresh to try again.");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [api, projectId]);

  const refreshLists = useCallback(async () => {
    if (!api) return;
    try {
      const [jobList, reportList] = await Promise.all([
        api.listJobs({ limit: 50 }),
        api.listReports({ projectId, limit: 20 }),
      ]);
      setJobs(jobList.filter((j) => j.project_id === projectId));
      setReports(reportList);
    } catch {
      // Non-fatal; lists may be stale after navigation back.
    }
  }, [api, projectId]);

  function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    setFileError(null);
    const selected = event.target.files?.[0] ?? null;
    if (!selected) {
      setFile(null);
      return;
    }
    if (!selected.name.toLowerCase().endsWith(".zip")) {
      setFile(null);
      setFileError("Only .zip source archives are supported.");
      return;
    }
    if (quota && selected.size > quota.max_source_bytes) {
      setFile(null);
      setFileError(
        `This archive is ${formatBytes(selected.size)} — the maximum allowed size is ${formatBytes(quota.max_source_bytes)}.`
      );
      return;
    }
    if (selected.size === 0) {
      setFile(null);
      setFileError("The selected file is empty.");
      return;
    }
    setFile(selected);
  }

  async function handleStartScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!api) return;
    setFileError(null);
    setLoadError(null);

    if (!file) {
      setFileError("Select a source ZIP to scan first.");
      return;
    }

    setUploading(true);
    try {
      // 1. Signed upload request (path + one-time URL).
      setUploadStage("Requesting secure upload link…");
      const signed = await api.signUpload();

      // 2. Upload directly to storage using the signed URL (no auth header).
      setUploadStage(`Uploading ${file.name} (${formatBytes(file.size)})…`);
      const putResponse = await fetch(signed.upload_url, {
        method: "PUT",
        body: file,
        headers: { "Content-Type": "application/zip" },
      });
      if (!putResponse.ok) {
        throw new ApiError(
          putResponse.status,
          putResponse.status === 413
            ? "The uploaded file exceeds the maximum allowed size."
            : "The upload failed. Please try again."
        );
      }

      // 3. Create the scan job referencing the stored object.
      setUploadStage("Creating scan job…");
      const checksum = await sha256Hex(file);
      const job = await api.createJob({
        upload_path: signed.path,
        project_id: projectId,
        scan_profile: profile,
        source_bytes: file.size,
        ...(checksum ? { source_sha256: checksum } : {}),
      });

      router.push(`/scans/${job.id}`);
    } catch (err) {
      if (err instanceof ApiError) {
        setFileError(err.message);
      } else if (err instanceof TypeError) {
        setFileError("Network error during upload — please check your connection and try again.");
      } else {
        setFileError("The scan could not be started. Please try again.");
      }
      void refreshLists();
    } finally {
      setUploading(false);
      setUploadStage(null);
    }
  }

  if (initializing) return <Loading label="Checking your session…" />;

  if (notFound) {
    return (
      <div className="container">
        <div className="empty-state">
          <h1>Project not found</h1>
          <p className="mb-6">
            This project doesn&apos;t exist or you don&apos;t have access to it.
          </p>
          <Link href="/dashboard" className="btn btn-primary">
            Back to dashboard
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="container">
      <div className="page-header">
        <p className="text-sm text-dim mb-2">
          <Link href="/dashboard">Dashboard</Link> / Projects
        </p>
        <h1>{project ? project.name : "…"}</h1>
        {project && (
          <p className="text-sm text-muted mt-2">Created {formatDateTime(project.created_at)}</p>
        )}
      </div>

      {(loadError || hookError) && (
        <div className="mb-4">
          <ErrorAlert message={loadError ?? hookError ?? ""} />
        </div>
      )}

      {/* ── Start a new scan ──────────────────────────────────────────── */}
      <section className="card mb-6">
        <h2 style={{ marginBottom: "var(--space-2)" }}>Start a scan</h2>
        <p className="text-sm text-muted mb-4">
          Upload the source code of the target as a ZIP archive. The archive is
          scanned in an isolated worker and is never shared with other users.
        </p>
        <form onSubmit={handleStartScan} noValidate>
          <div className="flex flex-col gap-4">
            <div className="form-group">
              <label className="form-label" htmlFor="scan-file">
                Source archive (.zip)
              </label>
              <input
                id="scan-file"
                ref={fileInputRef}
                type="file"
                accept=".zip,application/zip"
                className="form-input"
                onChange={handleFileChange}
                disabled={uploading}
                aria-invalid={Boolean(fileError)}
              />
              {quota && (
                <span className="text-xs text-dim">
                  Maximum size: {formatBytes(quota.max_source_bytes)}
                </span>
              )}
            </div>

            <div className="form-group" style={{ maxWidth: 280 }}>
              <label className="form-label" htmlFor="scan-profile">
                Scan profile
              </label>
              <select
                id="scan-profile"
                className="form-input"
                value={profile}
                onChange={(e) => setProfile(e.target.value as ScanProfile)}
                disabled={uploading}
              >
                {SCAN_PROFILES.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            </div>

            {fileError && <ErrorAlert message={fileError} />}
            {uploading && uploadStage && (
              <div className="loading-container" style={{ padding: 0 }}>
                <span className="spinner" aria-hidden="true" />
                <span>{uploadStage}</span>
              </div>
            )}

            <div>
              <button type="submit" className="btn btn-primary" disabled={uploading}>
                {uploading ? "Starting scan…" : "Upload & start scan"}
              </button>
            </div>
          </div>
        </form>
      </section>

      {/* ── Scans ─────────────────────────────────────────────────────── */}
      <section className="card mb-6">
        <h2 style={{ marginBottom: "var(--space-4)" }}>Scans</h2>
        {jobs === null ? (
          <Loading label="Loading scans…" />
        ) : jobs.length === 0 ? (
          <EmptyState title="No scans yet">
            <p>Upload a source ZIP above to run your first scan on this project.</p>
          </EmptyState>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Scan</th>
                  <th>Profile</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th aria-label="Actions" />
                </tr>
              </thead>
              <tbody>
                {jobs.map((job) => (
                  <tr key={job.id}>
                    <td>
                      <Link href={`/scans/${job.id}`} className="font-mono text-sm">
                        {job.id.slice(0, 8)}…
                      </Link>
                    </td>
                    <td className="text-muted">{job.scan_profile}</td>
                    <td>
                      <JobStatusBadge status={job.status} />
                    </td>
                    <td className="text-muted">{formatDateTime(job.created_at)}</td>
                    <td>
                      <Link href={`/scans/${job.id}`} className="btn btn-secondary btn-sm">
                        View
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* ── Reports ───────────────────────────────────────────────────── */}
      <section className="card">
        <h2 style={{ marginBottom: "var(--space-4)" }}>Reports</h2>
        {reports === null ? (
          <Loading label="Loading reports…" />
        ) : reports.length === 0 ? (
          <EmptyState title="No reports yet">
            <p>Completed scans produce a report with all findings.</p>
          </EmptyState>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Report</th>
                  <th>Target</th>
                  <th>Created</th>
                  <th aria-label="Actions" />
                </tr>
              </thead>
              <tbody>
                {reports.map((report) => (
                  <tr key={report.report_id}>
                    <td>
                      <Link href={`/reports/${report.report_id}`} className="font-mono text-sm">
                        {report.report_id.slice(0, 8)}…
                      </Link>
                    </td>
                    <td className="text-muted">{report.target_label}</td>
                    <td className="text-muted">{formatDateTime(report.created_at)}</td>
                    <td>
                      <Link href={`/reports/${report.report_id}`} className="btn btn-secondary btn-sm">
                        Open
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
