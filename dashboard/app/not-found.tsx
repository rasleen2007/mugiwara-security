/**
 * 404 page — deliberate, user-friendly, no stack traces or internals.
 */

import Link from "next/link";

export default function NotFound() {
  return (
    <div className="container">
      <div className="empty-state" style={{ paddingTop: "var(--space-12)" }}>
        <p className="font-mono text-sm text-dim">404</p>
        <h1 style={{ marginBottom: "var(--space-2)" }}>
          This page doesn&apos;t exist
        </h1>
        <p className="mb-6">
          The page you are looking for was moved, removed, or never existed.
          The resource you requested may also have been deleted or belongs to
          another account.
        </p>
        <Link href="/dashboard" className="btn btn-primary">
          Back to dashboard
        </Link>
      </div>
    </div>
  );
}
