"use client";

/**
 * React hook that yields an API client bound to the current Supabase
 * session access token.
 *
 * - The token is read from supabase.auth.getSession() (cookie-backed session,
 *   never localStorage-managed by this app).
 * - If no session exists, the caller is redirected to /login.
 * - On a 401 from the API, the hook's error handler also redirects to
 *   /login so expired sessions recover automatically.
 *
 * Returns { api, loading, error } — `api` is null while the session is
 * being resolved or when unauthenticated.
 */

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { ApiError, createApiClient, type ApiClient } from "@/lib/api-client";
import { createClient } from "@/lib/supabase/client";

export interface UseApiResult {
  api: ApiClient | null;
  /** True until the session has been resolved at least once. */
  initializing: boolean;
  /** Set when session resolution itself failed. */
  error: string | null;
}

export function useApiClient(): UseApiResult {
  const router = useRouter();
  const [api, setApi] = useState<ApiClient | null>(null);
  const [initializing, setInitializing] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function resolve() {
      try {
        const supabase = createClient();
        const {
          data: { session },
        } = await supabase.auth.getSession();
        if (cancelled) return;
        if (!session) {
          router.replace("/login");
          return;
        }
        setApi(createApiClient(session.access_token));
      } catch {
        if (!cancelled) {
          setError("Could not establish your session. Please sign in again.");
        }
      } finally {
        if (!cancelled) setInitializing(false);
      }
    }

    void resolve();
    return () => {
      cancelled = true;
    };
  }, [router]);

  /** Shared handler for API failures inside client pages. */
  const handleApiError = useCallback(
    (err: unknown): string => {
      if (err instanceof ApiError && err.status === 401) {
        // Session expired server-side → force re-authentication.
        router.replace("/login");
        return "Your session has expired. Redirecting to sign-in…";
      }
      if (err instanceof ApiError) {
        return err.detail ? `${err.message}: ${err.detail}` : err.message;
      }
      if (err instanceof TypeError) {
        return "Network error — could not reach the Mugiwara service. Check your connection and try again.";
      }
      return "Something went wrong. Please try again.";
    },
    [router]
  );

  return { api, initializing, error };
}
