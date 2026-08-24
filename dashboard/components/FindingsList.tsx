/**
 * Findings display — presentational component rendering the scan findings.
 *
 * UX rules:
 * - Severity and verification status badges use security-product wording.
 * - UNVERIFIED / SUSPECTED findings are explicitly labelled as such and
 *   never styled like confirmed vulnerabilities.
 * - Content is rendered as text only (no dangerouslySetInnerHTML).
 */

import FindingStatusBadge from "@/components/FindingStatusBadge";
import SeverityBadge from "@/components/SeverityBadge";
import type { ScanFinding } from "@/lib/types";

function LocationLine({ finding }: { finding: ScanFinding }) {
  if (!finding.location?.file_path) return null;
  const loc = finding.location;
  const line =
    loc.start_line != null
      ? `:${loc.start_line}${loc.end_line != null ? `-${loc.end_line}` : ""}`
      : "";
  return (
    <p className="finding-location">
      {loc.file_path}
      {line}
    </p>
  );
}

export default function FindingsList({ findings }: { findings: ScanFinding[] }) {
  if (findings.length === 0) {
    return (
      <div className="empty-state">
        <h3>No findings</h3>
        <p>The scan completed without producing findings for this target.</p>
      </div>
    );
  }

  return (
    <div>
      {findings.map((finding, index) => (
        <article key={finding.id ?? index} className="finding-card">
          <div className="finding-header">
            <div>
              <h3 className="finding-title">{finding.title}</h3>
              {finding.category && (
                <span className="text-xs text-dim font-mono">{finding.category}</span>
              )}
            </div>
            <div className="finding-badges">
              {finding.status && <FindingStatusBadge status={finding.status} />}
              <SeverityBadge severity={finding.severity} />
              {finding.cvss_score != null && (
                <span className="badge badge-severity-info" title="CVSS score">
                  CVSS {finding.cvss_score}
                </span>
              )}
            </div>
          </div>

          <LocationLine finding={finding} />

          <div className="finding-section">
            <h4>Description</h4>
            <p>{finding.description}</p>
          </div>

          {finding.location?.snippet && (
            <pre className="finding-snippet">{finding.location.snippet}</pre>
          )}

          {finding.evidence?.summary && (
            <div className="finding-section">
              <h4>Evidence</h4>
              <p>{finding.evidence.summary}</p>
            </div>
          )}

          {finding.remediation?.summary && (
            <div className="finding-section">
              <h4>Remediation</h4>
              <p>{finding.remediation.summary}</p>
            </div>
          )}
        </article>
      ))}
    </div>
  );
}
