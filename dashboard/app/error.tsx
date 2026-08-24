"use client";

/**
 * Global error boundary — catches unexpected rendering errors.
 * Deliberately does NOT render the error details/stack (they can contain
 * internals); offers a retry and navigation back to the dashboard.
 */

import Link from "next/link";

export default function GlobalError({ reset }: { error: Error; reset: () => void }) {
  return (
    <div className="container">
      <div className="empty-state" style={{ paddingTop: "var(--space-12)" }}>
        <h1 style={{ marginBottom: "var(--space-2)" }}>Something went wrong</h1>
        <p className="mb-6">
          An unexpected error occurred while loading this page. Please try
          again. If the problem persists, go back to the dashboard.
        </p>
        <div className="flex items-center gap-4" style={{ justifyContent: "center" }}>
          <button type="button" className="btn btn-primary" onClick={reset}>
            Try again
          </button>
          <Link href="/dashboard" className="btn btn-secondary">
            Back to dashboard
          </Link>
        </div>
      </div>
    </div>
  );
}
