"use client";

/**
 * "Set a new password" form used after a Supabase password-recovery link.
 *
 * The user reaches here via /auth/callback (which exchanged the recovery
 * code for a session) carrying `next=/auth/update-password`. The recovery
 * session is still active, so auth.updateUser({ password }) sets the new
 * password securely. On success the user is offered a path back to /login.
 */

import Link from "next/link";
import { useState, type FormEvent } from "react";
import ErrorAlert from "@/components/ErrorAlert";
import { createClient } from "@/lib/supabase/client";
import {
  validatePasswordConfirmation,
  validateSignupPassword,
} from "@/lib/validators";

interface FieldErrors {
  password?: string;
  confirmPassword?: string;
}

function UpdatePasswordFormInner() {
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(null);

    const errors: FieldErrors = {
      password: validateSignupPassword(password) ?? undefined,
      confirmPassword:
        validatePasswordConfirmation(password, confirmPassword) ?? undefined,
    };
    setFieldErrors(errors);
    if (errors.password || errors.confirmPassword) return;

    setSubmitting(true);
    try {
      const supabase = createClient();
      const { error } = await supabase.auth.updateUser({ password });
      if (error) {
        setFormError(
          "We couldn't update your password. The reset link may have " +
            "expired — please request a new one."
        );
        return;
      }
      setSuccess(true);
    } catch {
      setFormError(
        "Could not reach the authentication service. Check your connection and try again."
      );
    } finally {
      setSubmitting(false);
    }
  }

  if (success) {
    return (
      <div>
        <div className="alert alert-success" role="status">
          <strong>Password updated!</strong> Your password has been changed
          successfully. You can now sign in with your new password.
        </div>
        <p className="text-sm text-muted mt-4" style={{ textAlign: "center" }}>
          <Link href="/login" className="font-medium">
            Continue to sign in
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
        <label className="form-label" htmlFor="new-password">
          New password
        </label>
        <input
          id="new-password"
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
        <label className="form-label" htmlFor="confirm-new-password">
          Confirm new password
        </label>
        <input
          id="confirm-new-password"
          type="password"
          className="form-input"
          autoComplete="new-password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          placeholder="Repeat your new password"
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
        {submitting ? "Updating password…" : "Set new password"}
      </button>
    </form>
  );
}

export default function UpdatePasswordForm() {
  return <UpdatePasswordFormInner />;
}
