/** Client-side form validation helpers (pure functions, easily testable). */

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Minimum signup password length. Matches the Supabase Auth default minimum;
 * if the hosted project enforces a stricter policy, the provider's own error
 * is surfaced as a safe user-facing message instead.
 */
export const SIGNUP_MIN_PASSWORD_LENGTH = 6;

export function validateEmail(email: string): string | null {
  if (!email.trim()) return "Email is required.";
  if (!EMAIL_PATTERN.test(email.trim())) return "Enter a valid email address.";
  return null;
}

/** Login-side check: presence only (never blocks existing accounts). */
export function validatePassword(password: string): string | null {
  if (!password) return "Password is required.";
  return null;
}

/** Signup-side check: presence plus the provider's minimum length. */
export function validateSignupPassword(password: string): string | null {
  if (!password) return "Password is required.";
  if (password.length < SIGNUP_MIN_PASSWORD_LENGTH) {
    return `Password must be at least ${SIGNUP_MIN_PASSWORD_LENGTH} characters.`;
  }
  return null;
}

export function validatePasswordConfirmation(
  password: string,
  confirmation: string
): string | null {
  if (!confirmation) return "Please confirm your password.";
  if (password !== confirmation) return "Passwords do not match.";
  return null;
}

export function validateProjectName(name: string): string | null {
  const trimmed = name.trim();
  if (!trimmed) return "Project name is required.";
  if (trimmed.length > 200)
    return "Project name must be at most 200 characters.";
  return null;
}
