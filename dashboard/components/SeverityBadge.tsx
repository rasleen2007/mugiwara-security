/**
 * Severity badge — renders CRITICAL/HIGH/MEDIUM/LOW/INFO pills.
 * Colors come from CSS custom properties; unknown values render as INFO-style.
 */

import type { Severity } from "@/lib/types";

const LABELS: Record<Severity, string> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  INFO: "Info",
};

export function severityClass(severity: string): string {
  switch (severity) {
    case "CRITICAL":
      return "badge-severity-critical";
    case "HIGH":
      return "badge-severity-high";
    case "MEDIUM":
      return "badge-severity-medium";
    case "LOW":
      return "badge-severity-low";
    default:
      return "badge-severity-info";
  }
}

export default function SeverityBadge({ severity }: { severity: string }) {
  const known = severity in LABELS;
  return (
    <span className={`badge ${severityClass(severity)}`}>
      {known ? LABELS[severity as Severity] : severity}
    </span>
  );
}
