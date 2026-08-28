"use client";

/**
 * Email/password signup form backed by Supabase Auth.
 *
 * Behaviour:
 * - Client-side validation (email, minimum password length, confirmation
 *   match) runs before any network call.
 * - If the provider creates a session immediately (email confirmation
 *   disabled), the user is redirected to /dashboard through the existing
 *   cookie-based session architecture — identical to a normal login.
 * - If email confirmation is required, NO session exists yet: we show a
 *   clear "check your email" message instead of pretending the user is
 *   authenticated. The confirmation link itself is handled by Supabase;
 *   after confirming, the user signs in via /login.
 * - Provider errors are mapped to safe user-facing messages; internals are
 *   never echoed. An already-registered email is reported without revealing
 *   whether any other account state exists.
 */

import Link from "next/link";
import { useState, type FormEvent } from "react";
import ErrorAlert from "@/components/ErrorAlert";
import { navigateTo } from "@/lib/navigate";
import { createClient } from "@/lib/supabase/client";
import {
  validateEmail,
  validatePasswordConfirmation,
  validateSignupPassword,
} from "@/lib/validators";

interface FieldErrors {
  email?: string;
  password?: string;
  confirmPassword?: string;
}

/**
 * Map an auth error to a safe message; never surface provider internals.
 *
 * Anti-abuse note: Supabase limits the volume of auth emails (and thus
 * signups) per project (the built-in email provider allows only ~2 emails
 * per hour project-wide). This is a deliberate abuse-protection boundary and
 * MUST NOT be bypassed in application code; it is only configurable in the
 * Supabase dashboard (custom SMTP + auth rate limits). We surface it to the
 * user as a temporary condition with a safe, actionable message instead.
 */
export function mapSignupError(message: string): string {
  const normalized = message.toLowerCase();

  if (
    normalized.includes("too many signup attempts") ||
    normalized.includes("too many sign up") ||
    normalized.includes("email rate limit") ||
    normalized.includes("rate limit exceeded") ||
    normalized.includes("rate limit") ||
    normalized.includes("too many requests")
  ) {
    // Temporary provider-level rate limit (built-in SMTP email quota or the
    // auth signup rate limiter). Do NOT reveal internals; reassure the user.
    return (
      "Signup is temporarily rate-limited by our authentication provider. " +
      "Please wait a few minutes and try again. If the problem persists, sign " +
      "in to your existing account."
    );
  }
  if (
    normalized.includes("already registered") ||
    normalized.includes("already exists") ||
    normalized.includes("already been taken")
  ) {
    return "An account with this email already exists. Try signing in instead.";
  }
  if (normalized.includes("password should be")) {
    // Clean policy wording from the provider; safe and useful as-is.
    return message.charAt(0).toUpperCase() + message.slice(1);
  }
  if (normalized.includes("invalid email")) {
    return "Enter a valid email address.";
  }
  return "Could not create your account. Please check your details and try again.";
}

function SignupFormInner() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [confirmationRequired, setConfirmationRequired] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(null);
    setConfirmationRequired(false);

    const errors: FieldErrors = {
      email: validateEmail(email) ?? undefined,
      password: validateSignupPassword(password) ?? undefined,
      confirmPassword:
        validatePasswordConfirmation(password, confirmPassword) ?? undefined,
    };
    setFieldErrors(errors);
    if (errors.email || errors.password || errors.confirmPassword) return;

    setSubmitting(true);
    try {
      const supabase = createClient();
      const { data, error: authError } = await supabase.auth.signUp({
        email: email.trim(),
        password,
        options: {
          emailRedirectTo: `${window.location.origin}/auth/callback`,
        },
      });

      if (authError) {
        setFormError(mapSignupError(authError.message));
        return;
      }

      if (data.session) {
        // Confirmation disabled: the session is already established in the
        // HttpOnly cookies by @supabase/ssr. Full navigation so middleware
        // and server components pick up the fresh session.
        navigateTo("/dashboard");
        return;
      }

      // Session absent → email confirmation is required. Do NOT redirect;
      // the user is not authenticated until they confirm via the email link.
      setConfirmationRequired(true);
    } catch {
      setFormError(
        "Could not reach the authentication service. Check your connection and try again."
      );
    } finally {
      setSubmitting(false);
    }
  }

  if (confirmationRequired) {
    return (
      <div>
        <div className="alert alert-success" role="status">
          <strong>Account created!</strong> We sent a confirmation link to{" "}
          <strong>{email.trim()}</strong>. Check your inbox (and spam folder)
          and click the link to activate your account.
        </div>
        <p className="text-sm text-muted mt-4">
          Already confirmed?{" "}
          <Link href="/login" className="font-medium">
            Sign in
          </Link>
        </p>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} noValidate>
      {formError && (
        <div className="mb-4">
          <ErrorAlert message={formError} />
        </div>
      )}

      <div className="form-group mb-4">
        <label className="form-label" htmlFor="signup-email">
          Email
        </label>
        <input
          id="signup-email"
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

      <div className="form-group mb-4">
        <label className="form-label" htmlFor="signup-password">
          Password
        </label>
        <input
          id="signup-password"
          type="password"
          className="form-input"
          autoComplete="new-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="At least 6 characters"
          disabled={submitting}
          aria-invalid={Boolean(fieldErrors.password)}
        />
        {fieldErrors.password && (
          <span className="alert alert-error text-xs" role="alert">
            {fieldErrors.password}
          </span>
        )}
      </div>

      <div className="form-group mb-6">
        <label className="form-label" htmlFor="signup-confirm-password">
          Confirm password
        </label>
        <input
          id="signup-confirm-password"
          type="password"
          className="form-input"
          autoComplete="new-password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          placeholder="Repeat your password"
          disabled={submitting}
          aria-invalid={Boolean(fieldErrors.confirmPassword)}
        />
        {fieldErrors.confirmPassword && (
          <span className="alert alert-error text-xs" role="alert">
            {fieldErrors.confirmPassword}
          </span>
        )}
      </div>

      <button
        type="submit"
        className="btn btn-primary"
        disabled={submitting}
        style={{ width: "100%" }}
      >
        {submitting ? "Creating account…" : "Create account"}
      </button>

      <p className="text-sm text-muted mt-4" style={{ textAlign: "center" }}>
        Already have an account?{" "}
        <Link href="/login" className="font-medium">
          Log in
        </Link>
      </p>
    </form>
  );
}

export default function SignupForm() {
  return <SignupFormInner />;
}
