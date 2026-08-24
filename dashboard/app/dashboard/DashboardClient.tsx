"use client";

/**
 * Dashboard — project overview.
 *
 * Shows the user's projects (with create form), recent scan jobs, and quota.
 * All data comes from the Mugiwara API with the Supabase session token;
 * ownership is derived server-side from the JWT.
 */

import Link from "next/link";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import EmptyState from "@/components/EmptyState";
import ErrorAlert from "@/components/ErrorAlert";
import JobStatusBadge from "@/components/JobStatusBadge";
import Loading from "@/components/Loading";
import { ApiError } from "@/lib/api-client";
import { formatBytes, formatDateTime } from "@/lib/format";
import type { Job, Project, Quota, Report } from "@/lib/types";
import { useApiClient } from "@/lib/useApiClient";
import { validateProjectName } from "@/lib/validators";

export default function DashboardClient() {
  const { api, initializing, error: hookError } = useApiClient();
  const [projects, setProjects] = useState<Project[] | null>(null);
  const [jobs, setJobs] = useState<Job[] | null>(null);
  const [quota, setQuota] = useState<Quota | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [newName, setNewName] = useState("");
  const [nameError, setNameError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const load = useCallback(
    async (client: NonNullable<ReturnType<typeof useApiClient>["api"]>) => {
      setLoadError(null);
      try {
        const [projectList, jobList, quotaInfo] = await Promise.all([
          client.listProjects(50),
          client.listJobs({ limit: 10 }),
          client.getQuota(),
        ]);
        setProjects(projectList);
        setJobs(jobList);
        setQuota(quotaInfo);
      } catch (err) {
        setLoadError(
          err instanceof ApiError && err.status === 401
            ? "Your session has expired."
            : "Could not load your dashboard. Please refresh to try again."
        );
      }
    },
    []
  );

  useEffect(() => {
    if (api) void load(api);
  }, [api, load]);

  useEffect(() => {
    if (hookError) setLoadError(hookError);
  }, [hookError]);

  async function handleCreateProject(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setActionError(null);
    if (!api) return;

    const validation = validateProjectName(newName);
    setNameError(validation);
    if (validation) return;

    setCreating(true);
    try {
      await api.createProject(newName.trim());
      setNewName("");
      await load(api);
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setNameError("A project with this name already exists.");
      } else {
        setActionError("Could not create the project. Please try again.");
      }
    } finally {
      setCreating(false);
    }
  }

  if (initializing) return <Loading label="Checking your session…" />;

  if (loadError && projects === null) {
    return (
      <div className="container">
        <div className="page-header">
          <h1>Dashboard</h1>
        </div>
        <ErrorAlert message={loadError} />
      </div>
    );
  }

  return (
    <div className="container">
      <div className="page-header flex items-center justify-between gap-4">
        <h1>Dashboard</h1>
      </div>

      {(loadError || actionError) && (
        <div className="mb-4">
          <ErrorAlert message={actionError ?? loadError ?? ""} />
        </div>
      )}

      {/* ── Quota summary ─────────────────────────────────────────────── */}
      {quota && (
        <div className="stat-grid mb-6">
          <div className="stat-card">
            <div className="stat-value">{quota.max_jobs_per_day}</div>
            <div className="stat-label">Scans / day</div>
          </div>
          <div className="stat-card">
            <div className="stat-value">{quota.max_concurrent_running_jobs}</div>
            <div className="stat-label">Concurrent scans</div>
          </div>
          <div className="stat-card">
            <div className="stat-value">{formatBytes(quota.max_source_bytes)}</div>
            <div className="stat-label">Max source size</div>
          </div>
          <div className="stat-card">
            <div className="stat-value">{quota.max_queued_jobs}</div>
            <div className="stat-label">Max queued scans</div>
          </div>
        </div>
      )}

      <div className="flex flex-col gap-6">
        {/* ── Create project ────────────────────────────────────────── */}
        <section className="card">
          <h2 style={{ marginBottom: "var(--space-4)" }}>Create a project</h2>
          <form onSubmit={handleCreateProject} noValidate className="flex items-center gap-4">
            <div className="form-group" style={{ flex: 1 }}>
              <label className="form-label" htmlFor="project-name">
                Project name
              </label>
              <input
                id="project-name"
                className="form-input"
                value={newName}
                onChange={(e) => {
                  setNewName(e.target.value);
                  if (nameError) setNameError(null);
                }}
                placeholder="e.g. webshop-backend"
                maxLength={200}
                disabled={creating}
                aria-invalid={Boolean(nameError)}
              />
              {nameError && (
                <span className="alert alert-error text-xs" role="alert">
                  {nameError}
                </span>
              )}
            </div>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={creating}
              style={{ marginTop: "var(--space-5)" }}
            >
              {creating ? "Creating…" : "Create project"}
            </button>
          </form>
        </section>

        {/* ── Projects ──────────────────────────────────────────────── */}
        <section className="card">
          <h2 style={{ marginBottom: "var(--space-4)" }}>Projects</h2>
          {projects === null ? (
            <Loading label="Loading projects…" />
          ) : projects.length === 0 ? (
            <EmptyState title="No projects yet">
              <p>Create your first project above, then upload a source ZIP to start a scan.</p>
            </EmptyState>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Created</th>
                    <th aria-label="Actions" />
                  </tr>
                </thead>
                <tbody>
                  {projects.map((project) => (
                    <tr key={project.id}>
                      <td>
                        <Link href={`/projects/${project.id}`}>{project.name}</Link>
                      </td>
                      <td className="text-muted">{formatDateTime(project.created_at)}</td>
                      <td>
                        <Link href={`/projects/${project.id}`} className="btn btn-secondary btn-sm">
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

        {/* ── Recent scans ──────────────────────────────────────────── */}
        <section className="card">
          <h2 style={{ marginBottom: "var(--space-4)" }}>Recent scans</h2>
          {jobs === null ? (
            <Loading label="Loading scan jobs…" />
          ) : jobs.length === 0 ? (
            <EmptyState title="No scans yet">
              <p>Open a project and upload a source ZIP to start scanning.</p>
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
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
