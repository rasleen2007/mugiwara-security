/**
 * Scan job status badge — queued/running/completed/failed/cancelled.
 */

export function jobStatusClass(status: string): string {
  switch (status) {
    case "queued":
      return "badge-job-queued";
    case "running":
      return "badge-job-running";
    case "completed":
      return "badge-job-completed";
    case "failed":
      return "badge-job-failed";
    default:
      return "badge-job-cancelled";
  }
}

export default function JobStatusBadge({ status }: { status: string }) {
  return <span className={`badge ${jobStatusClass(status)}`}>{status}</span>;
}
