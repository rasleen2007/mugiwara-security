/** Loading state with spinner. */

export default function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="loading-container" role="status" aria-live="polite">
      <span className="spinner" aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}
