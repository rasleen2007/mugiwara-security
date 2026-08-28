"use client";

/**
 * "Forgot password?" email request form.
 *
 * Uses Supabase's official password recovery flow
 * (auth.resetPasswordForEmail). Regardless of whether the email exists, the
 * user always sees the same success message so we never reveal which email
 * addresses are registered. The reset email links back to /auth/callback,
 * which exchanges the recovery code and forwards the user to
 * /auth/update-password to set a new password.
 */

import Link from "next/link";
import { useState, type FormEvent } from "react";
import ErrorAlert from "@/components/ErrorAlert";
import { createClient } from "@/lib/supabase/client";
import { validateEmail } from "@/lib/validators";

function ForgotPasswordFormInner() {
  const [email, setEmail] = useState("");
  const [fieldError, setFieldError] = useState<string | undefined>(undefined);
  const [formError, setFormError] = useState<string | null>(null);
  const [submitted, setSubmitted] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  // Absolute redirect URL used by the recovery email. `next` carries the
  // destination for the auth callback so the user ends up on the
  // "set new password" screen after the code is exchanged.
  const redirectTo =
    typeof window !== "undefined"
      ? `${window.location.origin}/auth/callback?next=/auth/update-password`
      : undefined;

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(null);

    const error = validateEmail(email);
    setFieldError(error ?? undefined);
    if (error) return;

    setSubmitting(true);
    try {
      const supabase = createClient();
      // Even when auth.resetPasswordForEmail fails (unknown email, rate
      // limited, etc.) we show the SAME message so the user cannot tell
      // whether an account exists. Rate limits are a Supabase abuse
      // protection and are deliberately not bypassed here.
      await supabase.auth.resetPasswordForEmail(email.trim(), {
        redirectTo,
      });
      setSubmitted(true);
    } catch {
      // A thrown network failure should not leak that we know the email
      // exists either; reuse the identical generic success message.
      setSubmitted(true);
    } finally {
      setSubmitting(false);
    }
  }

  if (submitted) {
    return (
      <div>
        <div className="alert alert-success" role="status">
          If an account exists for <strong>{email.trim()}</strong>, we&apos;ve
          sent you a link to reset your password. Check your inbox (and spam
          folder) and follow the instructions.
        </div>
        <p className="text-sm text-muted mt-4" style={{ textAlign: "center" }}>
          Remembered your password?{" "}
          <Link href="/login" className="font-medium">
            Back to sign in
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

      <div className="form-group mb-6">
        <label className="form-label" htmlFor="forgot-password-email">
          Email
        </label>
        <input
          id="forgot-password-email"
          type="email"
          className="form-input"
          autoComplete="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@example.com"
          disabled={submitting}
          aria-invalid={Boolean(fieldError)}
        />
        {fieldError && (
          <span className="alert alert-error text-xs" role="alert">
            {fieldError}
          </span>
        )}
      </div>

      <button
        type="submit"
        className="btn btn-primary"
        disabled={submitting}
        style={{ width: "100%" }}
      >
        {submitting ? "Sending reset link…" : "Send reset link"}
      </button>

      <p className="text-sm text-muted mt-4" style={{ textAlign: "center" }}>
        Remembered your password?{" "}
        <Link href="/login" className="font-medium">
          Back to sign in
        </Link>
      </p>
    </form>
  );
}

export default function ForgotPasswordForm() {
  return <ForgotPasswordFormInner />;
}
