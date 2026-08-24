/**
 * Centralized Mugiwara cloud API client.
 *
 * Security guarantees:
 * - The token is always obtained from the Supabase session, never from
 *   application state, localStorage, cookies read by JS, or any client-
 *   controlled source other than the Supabase auth session.
 * - The Authorization header value is NEVER logged.
 * - The base URL is always read from the NEXT_PUBLIC_MUGIWARA_API_URL
 *   environment variable; missing config fails loudly at call time.
 * - No owner_id / user_id / server-controlled fields are sent in request
 *   bodies — callers must not add them.
 * - Signed storage URLs returned by the API are consumed immediately and
 *   must not be persisted to application state unnecessarily.
 */

import type {
  Job,
  MeOut,
  Project,
  Quota,
  Report,
  ScanEnvelope,
  SignedUpload,
} from "@/lib/types";

// ── Error types ───────────────────────────────────────────────────────────

/** Errors surfaced from the Mugiwara API with a known HTTP status code. */
export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly detail?: string
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/** Thrown when the NEXT_PUBLIC_MUGIWARA_API_URL variable is absent. */
export class ApiConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ApiConfigError";
  }
}

// ── Internal helpers ──────────────────────────────────────────────────────

function getApiBaseUrl(): string {
  const url = process.env.NEXT_PUBLIC_MUGIWARA_API_URL;
  if (!url) {
    throw new ApiConfigError(
      "NEXT_PUBLIC_MUGIWARA_API_URL is not configured. " +
        "Add it to .env.local (see .env.local.example)."
    );
  }
  return url.replace(/\/$/, "");
}

/** Convert an HTTP status code into a user-facing message. */
function statusToMessage(status: number): string {
  if (status === 401) return "Your session has expired. Please sign in again.";
  if (status === 403) return "You do not have permission to access this resource.";
  if (status === 404) return "The requested resource was not found.";
  if (status === 409)
    return "This operation conflicts with the current state. The resource may have changed.";
  if (status === 413) return "The uploaded file exceeds the maximum allowed size.";
  if (status === 429)
    return "Request limit reached. Please wait before trying again.";
  if (status >= 500)
    return "The service is temporarily unavailable. Please try again later.";
  return `Request failed (${status}).`;
}

/**
 * Parse the response, surfacing clean ApiError on failure.
 * Never exposes raw backend detail strings for ≥500 errors.
 */
async function parseResponse<T>(response: Response): Promise<T> {
  if (response.status === 204) return undefined as T;
  if (response.ok) {
    return response.json() as Promise<T>;
  }

  let serverDetail: string | undefined;
  try {
    const body = (await response.json()) as Record<string, unknown>;
    if (typeof body["detail"] === "string") {
      serverDetail = body["detail"];
    }
  } catch {
    // ignore JSON parse failure on error bodies
  }

  // For 5xx, never surface server detail to the browser.
  const userDetail = response.status >= 500 ? undefined : serverDetail;
  const message = statusToMessage(response.status);
  throw new ApiError(response.status, message, userDetail);
}

/**
 * Core fetch wrapper.
 *
 * @param token   - Supabase access_token obtained from supabase.auth.getSession().
 *                  MUST NOT be logged.
 * @param path    - API path (e.g. "/api/projects").
 * @param options - Optional fetch options (method, body, etc.).
 *                  Do NOT include Authorization in options.headers; it is
 *                  added here and only here.
 */
async function apiRequest<T>(
  token: string,
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const baseUrl = getApiBaseUrl();
  const url = `${baseUrl}${path}`;

  const { headers: extraHeaders, ...rest } = options;
  const response = await fetch(url, {
    ...rest,
    headers: {
      "Content-Type": "application/json",
      ...(extraHeaders ?? {}),
      // Authorization must come last so callers cannot override it.
      Authorization: `Bearer ${token}`,
    },
    // Always bypass Next.js cache for API calls that read user data.
    cache: "no-store",
  });

  return parseResponse<T>(response);
}

// ── Public API factory ────────────────────────────────────────────────────

/**
 * Build a typed API client bound to the given access token.
 *
 * Usage in Server Components:
 *   const supabase = createServerClient()
 *   const { data: { session } } = await supabase.auth.getSession()
 *   if (!session) redirect('/login')
 *   const api = createApiClient(session.access_token)
 *
 * Usage in Client Components:
 *   const supabase = createBrowserClient()
 *   const { data: { session } } = await supabase.auth.getSession()
 *   if (!session) { router.push('/login'); return }
 *   const api = createApiClient(session.access_token)
 */
export function createApiClient(token: string) {
  const req = <T>(path: string, options?: RequestInit) =>
    apiRequest<T>(token, path, options);

  return {
    // ── Auth ───────────────────────────────────────────────────────────
    me(): Promise<MeOut> {
      return req<MeOut>("/api/me");
    },

    // ── Projects ───────────────────────────────────────────────────────
    listProjects(limit = 50): Promise<Project[]> {
      return req<Project[]>(`/api/projects?limit=${limit}`);
    },
    getProject(projectId: string): Promise<Project> {
      return req<Project>(`/api/projects/${encodeURIComponent(projectId)}`);
    },
    createProject(name: string): Promise<Project> {
      return req<Project>("/api/projects", {
        method: "POST",
        body: JSON.stringify({ name }),
      });
    },
    deleteProject(projectId: string): Promise<void> {
      return req<void>(
        `/api/projects/${encodeURIComponent(projectId)}`,
        { method: "DELETE" }
      );
    },

    // ── Uploads ────────────────────────────────────────────────────────
    signUpload(): Promise<SignedUpload> {
      return req<SignedUpload>("/api/uploads/sign", { method: "POST" });
    },

    // ── Scan jobs ──────────────────────────────────────────────────────
    listJobs(opts: { limit?: number; status?: string; projectId?: string } = {}): Promise<Job[]> {
      const params = new URLSearchParams();
      if (opts.limit) params.set("limit", String(opts.limit));
      if (opts.status) params.set("status", opts.status);
      const qs = params.toString();
      return req<Job[]>(`/api/jobs${qs ? `?${qs}` : ""}`);
    },
    getJob(jobId: string): Promise<Job> {
      return req<Job>(`/api/jobs/${encodeURIComponent(jobId)}`);
    },
    createJob(payload: {
      upload_path: string;
      project_id?: string | null;
      scan_profile?: "fast" | "standard" | "deep";
      source_bytes?: number;
    }): Promise<Job> {
      return req<Job>("/api/jobs", {
        method: "POST",
        body: JSON.stringify(payload),
      });
    },
    cancelJob(jobId: string): Promise<Job> {
      return req<Job>(
        `/api/jobs/${encodeURIComponent(jobId)}/cancel`,
        { method: "POST" }
      );
    },

    // ── Reports ────────────────────────────────────────────────────────
    listReports(opts: { limit?: number; projectId?: string } = {}): Promise<Report[]> {
      const params = new URLSearchParams();
      if (opts.limit) params.set("limit", String(opts.limit));
      if (opts.projectId) params.set("project_id", opts.projectId);
      const qs = params.toString();
      return req<Report[]>(`/api/reports${qs ? `?${qs}` : ""}`);
    },
    getReport(reportId: string): Promise<Report> {
      return req<Report>(`/api/reports/${encodeURIComponent(reportId)}`);
    },
    /**
     * Fetch the full scan envelope for a report (JSON export format).
     * The returned object is used immediately for display and must not
     * be stored in persistent application state unnecessarily.
     */
    getReportEnvelope(reportId: string): Promise<ScanEnvelope> {
      return req<ScanEnvelope>(
        `/api/reports/${encodeURIComponent(reportId)}/export?format=json`
      );
    },
    getReportExportUrl(
      reportId: string,
      format: "markdown" | "sarif" | "json"
    ): string {
      const baseUrl = getApiBaseUrl();
      return `${baseUrl}/api/reports/${encodeURIComponent(reportId)}/export?format=${format}`;
    },

    // ── Quota ──────────────────────────────────────────────────────────
    getQuota(): Promise<Quota> {
      return req<Quota>("/api/quota");
    },
  };
}

export type ApiClient = ReturnType<typeof createApiClient>;
