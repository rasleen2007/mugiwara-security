/**
 * Finding status badge.
 *
 * UX rule: UNVERIFIED / SUSPECTED findings must NEVER be visually
 * represented as confirmed vulnerabilities — they use neutral/warning
 * styling and explicit wording, never red "confirmed" colors.
 */

const LABELS: Record<string, string> = {
  VERIFIED: "Verified",
  FALSE_POSITIVE: "False positive",
  SUSPECTED: "Suspected (unconfirmed)",
  UNVERIFIED: "Unverified",
  FIXED: "Fixed",
  VERIFIED_FIXED: "Verified fixed",
  NOT_FIXED: "Not fixed",
  FAILED: "Verification failed",
};

export function findingStatusClass(status: string): string {
  switch (status) {
    case "VERIFIED":
      return "badge-status-verified";
    case "FALSE_POSITIVE":
      return "badge-status-false-positive";
    case "FIXED":
    case "VERIFIED_FIXED":
      return "badge-status-fixed";
    case "SUSPECTED":
      return "badge-status-suspected";
    default:
      // UNVERIFIED, NOT_FIXED, FAILED, unknown → neutral treatment.
      return "badge-status-unverified";
  }
}

export default function FindingStatusBadge({ status }: { status: string }) {
  const label = LABELS[status] ?? status;
  return (
    <span className={`badge ${findingStatusClass(status)}`}>{label}</span>
  );
}
