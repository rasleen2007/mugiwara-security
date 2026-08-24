/**
 * Badge component tests — security terminology must be displayed exactly:
 * severity levels, finding statuses, and job statuses each map to the
 * correct CSS class so UNVERIFIED/SUSPECTED can never look like VERIFIED.
 */

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import FindingStatusBadge, {
  findingStatusClass,
} from "@/components/FindingStatusBadge";
import JobStatusBadge, { jobStatusClass } from "@/components/JobStatusBadge";
import SeverityBadge, { severityClass } from "@/components/SeverityBadge";

describe("SeverityBadge", () => {
  it.each(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])(
    "renders %s with its severity class",
    (severity) => {
      render(<SeverityBadge severity={severity} />);
      const badge = screen.getByText(new RegExp(`^${severity.charAt(0)}${severity.slice(1).toLowerCase()}$`));
      expect(badge.className).toBe(`badge badge-severity-${severity.toLowerCase()}`);
    }
  );

  it("renders unknown severities with a neutral class", () => {
    render(<SeverityBadge severity="UNKNOWN" />);
    expect(screen.getByText("UNKNOWN").className).toContain("badge-severity-info");
  });
});

describe("FindingStatusBadge", () => {
  it("labels suspected findings explicitly as unconfirmed", () => {
    render(<FindingStatusBadge status="SUSPECTED" />);
    expect(screen.getByText("Suspected (unconfirmed)")).toBeTruthy();
  });

  it("labels unverified findings as unverified", () => {
    render(<FindingStatusBadge status="UNVERIFIED" />);
    expect(screen.getByText("Unverified")).toBeTruthy();
  });

  it("uses distinct classes for verified vs unverified vs suspected", () => {
    expect(findingStatusClass("VERIFIED")).toBe("badge-status-verified");
    expect(findingStatusClass("UNVERIFIED")).not.toBe(findingStatusClass("VERIFIED"));
    expect(findingStatusClass("SUSPECTED")).not.toBe(findingStatusClass("VERIFIED"));
    expect(findingStatusClass("FALSE_POSITIVE")).toBe("badge-status-false-positive");
    expect(findingStatusClass("FIXED")).toBe("badge-status-fixed");
    expect(findingStatusClass("VERIFIED_FIXED")).toBe("badge-status-fixed");
    expect(findingStatusClass("NOT_FIXED")).toBe("badge-status-unverified");
    expect(findingStatusClass("FAILED")).toBe("badge-status-unverified");
  });
});

describe("JobStatusBadge", () => {
  it.each([
    ["queued", "badge-job-queued"],
    ["running", "badge-job-running"],
    ["completed", "badge-job-completed"],
    ["failed", "badge-job-failed"],
    ["cancelled", "badge-job-cancelled"],
  ])("renders %s with %s", (status, expectedClass) => {
    expect(jobStatusClass(status)).toBe(expectedClass);
    render(<JobStatusBadge status={status} />);
    expect(screen.getByText(status)).toBeTruthy();
  });
});
