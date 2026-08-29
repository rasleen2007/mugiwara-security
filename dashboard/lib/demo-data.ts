/**
 * Static demo dataset for the public /demo route (Guest/Demo Mode).
 *
 * PURPOSE:
 * - Lets visitors who have NOT signed up see what a Mugiwara report looks
 *   like, without creating an account or running a real scan.
 * - These are SAFE, hand-curated sample values that mirror the real API
 *   shapes (see ./types.ts) so the existing UI components can render them.
 *
 * IMPORTANT:
 * - This module is client-side-only sample content. It is NOT secret data
 *   and does NOT come from any real user's account.
 * - The /demo page must NEVER call authenticated API endpoints
 *   (/projects, /scans, /reports, /api/*) or use the auth token. Everything
 *   on it is whatever is defined in this file.
 */

import type { Job, Project, Report, ScanEnvelope, ScanFinding } from "./types";

export const DEMO_PROJECT_NAME = "sample-petstore-api";

export const DEMO_PROJECT: Project = {
  id: "demo-project-petstore",
  name: DEMO_PROJECT_NAME,
  created_at: "2026-08-20T10:15:00.000Z",
};

export const DEMO_REPORT: Report = {
  report_id: "demo-report-8f3a11c2",
  project_id: DEMO_PROJECT.id,
  origin: "directory",
  target_label: DEMO_PROJECT_NAME,
  summary: {
    total_findings: 8,
  },
  created_at: "2026-08-21T16:40:00.000Z",
};

export const DEMO_JOBS: Job[] = [
  {
    id: "demo-job-0c31f9be",
    project_id: DEMO_PROJECT.id,
    kind: "scan",
    status: "completed",
    target_kind: "directory",
    scan_profile: "standard",
    phases: [
      "Queued",
      "Collecting source…",
      "Mapping attack surface…",
      "Discovering likely vulnerabilities…",
      "Verifying candidates in isolated sandbox…",
      "Generating report…",
    ],
    error: null,
    attempts: 1,
    created_at: "2026-08-21T16:35:00.000Z",
    started_at: "2026-08-21T16:35:04.000Z",
    completed_at: "2026-08-21T16:40:00.000Z",
  },
  {
    id: "demo-job-7412aa0d",
    project_id: DEMO_PROJECT.id,
    kind: "scan",
    status: "completed",
    target_kind: "directory",
    scan_profile: "fast",
    phases: ["Queued", "Collecting source…", "Discovering likely vulnerabilities…", "Generating report…"],
    error: null,
    attempts: 1,
    created_at: "2026-08-22T09:05:00.000Z",
    started_at: "2026-08-22T09:05:03.000Z",
    completed_at: "2026-08-22T09:08:12.000Z",
  },
];

/**
 * Demo findings. These intentionally span severities and verification
 * statuses to show the honest-verification UX (VERIFIED vs SUSPECTED vs
 * FALSE_POSITIVE). They are illustrative sample findings only.
 */
export const DEMO_FINDINGS: ScanFinding[] = [
  {
    id: "demo-find-001",
    title: "SQL injection in login handler",
    description:
      "User-supplied input is concatenated into a SQL statement before execution, which can let an attacker alter the query logic.",
    category: "sql_injection",
    severity: "CRITICAL",
    status: "VERIFIED",
    cwe_id: "CWE-89",
    location: {
      file_path: "routes/auth.py",
      start_line: 24,
      snippet: 'cursor.execute(f"SELECT * FROM users WHERE name = \'{username}\'")',
    },
    evidence: {
      summary:
        "Verified in an isolated sandbox: a crafted username caused the query to return unintended rows, confirming the injection is reachable.",
    },
    remediation: {
      summary:
        "Use parameterized queries (e.g. cursor.execute('... %s', (username,))) so input is never treated as SQL.",
    },
  },
  {
    id: "demo-find-002",
    title: "Hardcoded secret committed to source",
    description:
      "A credential-looking literal is assigned directly in source code and committed to the repository.",
    category: "hardcoded_secret",
    severity: "HIGH",
    status: "SUSPECTED",
    cwe_id: "CWE-798",
    location: {
      file_path: "config.py",
      start_line: 11,
      snippet: 'API_KEY = "sk-live-abcdef123456"',
    },
  },
  {
    id: "demo-find-003",
    title: "Unsafe YAML deserialization",
    description:
      "yaml.load without an explicit safe loader can construct arbitrary objects, enabling remote code execution.",
    category: "remote_code_execution",
    severity: "HIGH",
    status: "SUSPECTED",
    cwe_id: "CWE-502",
    location: {
      file_path: "parsers.py",
      start_line: 18,
      snippet: "return yaml.load(stream)",
    },
  },
  {
    id: "demo-find-004",
    title: "Subprocess called with shell=True",
    description:
      "A subprocess invocation passes the command through a shell interpreter, which can allow command injection.",
    category: "command_injection",
    severity: "MEDIUM",
    status: "FALSE_POSITIVE",
    cwe_id: "CWE-78",
    location: {
      file_path: "utils.py",
      start_line: 41,
      snippet: 'subprocess.run(f"ls {path}", shell=True)',
    },
    evidence: {
      summary:
        "Probed in the sandbox: the interpolated value is validated and cannot break out of the command. Reported as a false positive.",
    },
  },
  {
    id: "demo-find-005",
    title: "Dynamic code evaluation with eval()",
    description:
      "Dynamic evaluation of code via eval can execute attacker-controllable input if it ever reaches an untrusted source.",
    category: "remote_code_execution",
    severity: "LOW",
    status: "SUSPECTED",
    cwe_id: "CWE-95",
    location: {
      file_path: "calc.py",
      start_line: 7,
      snippet: "result = eval(expression)",
    },
  },
];

/** Demo scan envelope mirroring the real mugiwara.scan-report export shape. */
export const DEMO_ENVELOPE: ScanEnvelope = {
  schema: "mugiwara.scan-report",
  report_id: DEMO_REPORT.report_id,
  created_at: DEMO_REPORT.created_at,
  scan: {
    target_path: DEMO_PROJECT_NAME,
    scan_profile: "standard",
    summary: {
      total_findings: DEMO_FINDINGS.length,
      by_severity: {
        CRITICAL: 1,
        HIGH: 2,
        MEDIUM: 1,
        LOW: 1,
        INFO: 0,
      },
      by_status: {
        VERIFIED: 1,
        SUSPECTED: 3,
        FALSE_POSITIVE: 1,
      },
    },
    findings: DEMO_FINDINGS,
  },
  target: {
    path: DEMO_PROJECT_NAME,
    origin: "directory",
    files_collected: 6,
  },
  configuration: {
    scan_profile: "standard",
    llm_provider: "demo",
    sandbox_mode: "isolated",
    verification_enabled: true,
    include_evidence: true,
  },
};
