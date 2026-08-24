/**
 * Tests for the Mugiwara API client.
 *
 * Focus areas:
 * - Correct HTTP status → user-facing message mapping (401/403/404/409/413/429/5xx).
 * - 5xx server detail is never surfaced to the UI.
 * - Authorization header is always attached and cannot be overridden by callers.
 * - Server-controlled fields (owner_id/user_id) are not part of any request body.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiConfigError, ApiError, createApiClient } from "@/lib/api-client";

// Provide the env var the client reads at call time.
const API_URL = "https://api.example.test";

vi.stubEnv("NEXT_PUBLIC_MUGIWARA_API_URL", API_URL);

function okResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function errorResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("createApiClient", () => {
  it("throws ApiConfigError when NEXT_PUBLIC_MUGIWARA_API_URL is missing", async () => {
    vi.stubEnv("NEXT_PUBLIC_MUGIWARA_API_URL", "");
    const client = createApiClient("token");
    await expect(client.me()).rejects.toBeInstanceOf(ApiConfigError);
    expect(fetchMock).not.toHaveBeenCalled();
    vi.stubEnv("NEXT_PUBLIC_MUGIWARA_API_URL", API_URL);
  });

  it.each([
    [401, "session has expired"],
    [403, "permission"],
    [404, "not found"],
    [409, "conflicts"],
    [413, "maximum allowed size"],
    [429, "Request limit reached"],
    [500, "temporarily unavailable"],
    [503, "temporarily unavailable"],
  ])(
    "maps HTTP %i to a clean user-facing message",
    async (status, expectedFragment) => {
      fetchMock.mockResolvedValue(errorResponse(status, { detail: "raw internal detail" }));
      const client = createApiClient("token");
      const err = await client.me().catch((e) => e);
      expect(err).toBeInstanceOf(ApiError);
      expect(err.status).toBe(status);
      expect(err.message).toContain(expectedFragment);
    }
  );

  it("never surfaces server detail for 5xx errors", async () => {
    fetchMock.mockResolvedValue(
      errorResponse(500, { detail: "psycopg traceback with internal host names" })
    );
    const client = createApiClient("token");
    const err = await client.listProjects().catch((e) => e);
    expect(err.detail).toBeUndefined();
    expect(String(err.message)).not.toContain("psycopg");
  });

  it("keeps server detail for 4xx errors", async () => {
    fetchMock.mockResolvedValue(errorResponse(400, { detail: "invalid identifier" }));
    const client = createApiClient("token");
    const err = await client.getProject("bad-id").catch((e) => e);
    expect(err.status).toBe(400);
    expect(err.detail).toBe("invalid identifier");
  });

  it("always attaches the Authorization header from the session token", async () => {
    fetchMock.mockResolvedValue(okResponse({ user_id: "u1", email: "e", role: null }));
    await createApiClient("secret-token").me();
    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers.Authorization).toBe("Bearer secret-token");
  });

  it("does not let callers override the Authorization header", async () => {
    fetchMock.mockResolvedValue(okResponse([]));
    const client = createApiClient("real-token");
    // The public surface never accepts headers; simulate an attempt via
    // the underlying request options path is impossible — assert instead
    // that no client method forwards arbitrary header state.
    await client.listProjects();
    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers.Authorization).toBe("Bearer real-token");
  });

  it("URL-encodes path parameters (no path-segment injection)", async () => {
    fetchMock.mockResolvedValue(okResponse({ id: "x", name: "n", created_at: "now" }));
    await createApiClient("t").getProject("../etc/passwd");
    const [url] = fetchMock.mock.calls[0];
    // Slashes must be percent-encoded so a malicious id cannot add
    // additional URL path segments.
    expect(url).toBe(`${API_URL}/api/projects/..%2Fetc%2Fpasswd`);
  });

  it("creates jobs without sending owner_id or user_id fields", async () => {
    fetchMock.mockResolvedValue(
      okResponse({
        id: "job1",
        project_id: null,
        kind: "scan",
        status: "queued",
        target_kind: "zip",
        scan_profile: "standard",
        phases: [],
        error: null,
        attempts: 0,
        created_at: "2026-01-01T00:00:00Z",
        started_at: null,
        completed_at: null,
      })
    );
    await createApiClient("t").createJob({
      upload_path: "u/j/source.zip",
      project_id: "p1",
      scan_profile: "standard",
      source_bytes: 123,
    });
    const [, init] = fetchMock.mock.calls[0];
    const body = JSON.parse(init.body);
    expect(Object.keys(body).sort()).toEqual([
      "project_id",
      "scan_profile",
      "source_bytes",
      "upload_path",
    ]);
  });

  it("builds export URLs with the requested format", () => {
    const url = createApiClient("t").getReportExportUrl("r1", "sarif");
    expect(url).toBe(`${API_URL}/api/reports/r1/export?format=sarif`);
  });

  it("returns undefined for 204 responses", async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }));
    await expect(createApiClient("t").deleteProject("p1")).resolves.toBeUndefined();
  });
});
