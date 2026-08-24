/**
 * TypeScript types mirroring the Mugiwara cloud API schemas.
 *
 * These are deliberately read-only views: the fields that the API returns
 * to the authenticated owner. Server-controlled fields (owner_id, etc.)
 * are intentionally absent — they must never be sent by the browser.
 */

// ── Projects ─────────────────────────────────────────────────────────────

export interface Project {
  id: string;
  name: string;
  created_at: string;
}

// ── Scan jobs ─────────────────────────────────────────────────────────────

export type JobStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export interface Job {
  id: string;
  project_id: string | null;
  kind: string;
  status: JobStatus;
  target_kind: string;
  scan_profile: string;
  phases: string[];
  error: string | null;
  attempts: number;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

// ── Uploads ───────────────────────────────────────────────────────────────

export interface SignedUpload {
  path: string;
  upload_url: string;
  expires_in: number;
}

// ── Reports ───────────────────────────────────────────────────────────────

export interface Report {
  report_id: string;
  project_id: string | null;
  origin: string;
  target_label: string;
  summary: Record<string, unknown>;
  created_at: string;
}

// ── Quota ─────────────────────────────────────────────────────────────────

export interface Quota {
  max_concurrent_running_jobs: number;
  max_queued_jobs: number;
  max_source_bytes: number;
  max_jobs_per_day: number;
}

// ── Finding / report envelope ─────────────────────────────────────────────

/** Severity levels — must match mugiwara.models.finding.Severity. */
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

/**
 * Finding status — the engine uses FindingStatus (SUSPECTED, VERIFIED,
 * FALSE_POSITIVE, FIXED). The UI displays these literally.
 */
export type FindingStatus =
  | "VERIFIED"
  | "FALSE_POSITIVE"
  | "SUSPECTED"
  | "FIXED"
  | "UNVERIFIED"; // defensive fallback for unknown values

export interface SourceLocation {
  file_path: string;
  start_line: number;
  end_line?: number | null;
  snippet?: string | null;
}

export interface FindingEvidence {
  summary?: string | null;
  raw_output?: string | null;
  reproduction_steps?: string | null;
}

export interface FindingRemediation {
  summary?: string | null;
  patch?: string | null;
  guidance?: string | null;
}

export interface ScanFinding {
  id?: string;
  title: string;
  description: string;
  category?: string;
  severity: Severity;
  /** The engine field is `status`, not `verification`. */
  status?: FindingStatus;
  cwe_id?: string | null;
  cvss_score?: number | null;
  location?: SourceLocation | null;
  evidence?: FindingEvidence | null;
  remediation?: FindingRemediation | null;
}

export interface ScanSummary {
  total_findings?: number;
  by_severity?: Partial<Record<Severity, number>>;
  by_status?: Record<string, number>;
  [key: string]: unknown;
}

/** Top-level mugiwara.scan-report JSON export envelope. */
export interface ScanEnvelope {
  schema: string;
  report_id: string;
  created_at: string;
  scan: {
    target_path?: string;
    scan_profile?: string;
    summary?: ScanSummary;
    findings: ScanFinding[];
  };
  target?: {
    path?: string;
    origin?: string;
    files_collected?: number;
  };
  configuration?: Record<string, unknown>;
}

// ── Auth ──────────────────────────────────────────────────────────────────

export interface MeOut {
  user_id: string;
  email: string | null;
  role: string | null;
}

// ── API error ─────────────────────────────────────────────────────────────

/** Terminal job statuses — polling should stop when one of these is reached. */
export const TERMINAL_JOB_STATUSES: ReadonlySet<JobStatus> = new Set<JobStatus>([
  "completed",
  "failed",
  "cancelled",
]);
