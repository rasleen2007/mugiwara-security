"use client";

/**
 * Email/password sign-in form backed by Supabase Auth.
 *
 * - On success the session is stored in HttpOnly cookies by @supabase/ssr
 *   (via middleware) and the user is moved to /dashboard or the ?next= URL.
 * - Error messages are generic; they never echo server internals.
 */

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState, type FormEvent } from "react";
import ErrorAlert from "@/components/ErrorAlert";
import { createClient } from "@/lib/supabase/client";
import { validateEmail, validatePassword } from "@/lib/validators";

function LoginFormInner() {
  const router = useRouter();
  const searchParams = useSearchParams();

  // Only allow relative internal redirect targets.
  const rawNext = searchParams.get("next") ?? "/dashboard";
  const nextPath = rawNext.startsWith("/") && !rawNext.startsWith("//") ? rawNext : "/dashboard";

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [fieldErrors, setFieldErrors] = useState<{ email?: string; password?: string }>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(null);

    const errors = {
      email: validateEmail(email) ?? undefined,
      password: validatePassword(password) ?? undefined,
    };
    setFieldErrors(errors);
    if (errors.email || errors.password) return;

    setSubmitting(true);
    try {
      const supabase = createClient();
      const { error: authError } = await supabase.auth.signInWithPassword({
        email: email.trim(),
        password,
      });
      if (authError) {
        // Generic message — never surface provider error details.
        setFormError(
          "Invalid email or password. Please check your credentials and try again."
        );
        return;
      }
      // Full navigation so middleware/server pick up the fresh session cookie.
      window.location.assign(nextPath);
    } catch {
      setFormError(
        "Could not reach the authentication service. Check your connection and try again."
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} noValidate>
      {formError && (
        <div className="mb-4">
          <ErrorAlert message={formError} />
        </div>
      )}

      <div className="form-group mb-4">
        <label className="form-label" htmlFor="login-email">
          Email
        </label>
        <input
          id="login-email"
          type="email"
          className="form-input"
          autoComplete="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@example.com"
          disabled={submitting}
          aria-invalid={Boolean(fieldErrors.email)}
        />
        {fieldErrors.email && (
          <span className="alert alert-error text-xs" role="alert">
            {fieldErrors.email}
          </span>
        )}
      </div>

      <div className="form-group mb-6">
        <label className="form-label" htmlFor="login-password">
          Password
        </label>
        <input
          id="login-password"
          type="password"
          className="form-input"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="••••••••"
          disabled={submitting}
          aria-invalid={Boolean(fieldErrors.password)}
        />
        {fieldErrors.password && (
          <span className="alert alert-error text-xs" role="alert">
            {fieldErrors.password}
          </span>
        )}
      </div>

      <button type="submit" className="btn btn-primary" disabled={submitting} style={{ width: "100%" }}>
        {submitting ? "Signing in…" : "Sign in"}
      </button>
    </form>
  );
}

/** Suspense boundary is required because useSearchParams() is used below. */
export default function LoginForm() {
  return (
    <Suspense fallback={<div className="loading-container"><span className="spinner" /></div>}>
      <LoginFormInner />
    </Suspense>
  );
}
