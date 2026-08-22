"""Scan report and summary data models for Mugiwara Security."""

from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from mugiwara.models.finding import Finding, FindingStatus, Severity


class ScanSummary(BaseModel):
    """Aggregated vulnerability metrics and counts for a scan session."""

    total_findings: int = Field(default=0, ge=0)
    critical_count: int = Field(default=0, ge=0)
    high_count: int = Field(default=0, ge=0)
    medium_count: int = Field(default=0, ge=0)
    low_count: int = Field(default=0, ge=0)
    info_count: int = Field(default=0, ge=0)
    verified_count: int = Field(default=0, ge=0)
    suspected_count: int = Field(default=0, ge=0)
    false_positive_count: int = Field(default=0, ge=0)
    fixed_count: int = Field(default=0, ge=0)


class ScanReport(BaseModel):
    """Represents the complete result of a security scan session."""

    id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for the scan report.",
    )
    target_path: str = Field(
        min_length=1,
        description="Target codebase path or URL analyzed during the scan.",
    )
    scan_profile: str = Field(
        default="standard",
        description="Scan profile used for this session (e.g. 'fast', 'standard', 'deep').",
    )
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the scan started (UTC).",
    )
    completed_at: datetime | None = Field(
        default=None,
        description="Timestamp when the scan completed (UTC).",
    )
    findings: list[Finding] = Field(
        default_factory=list,
        description="List of security vulnerability findings identified during the scan.",
    )
    summary: ScanSummary = Field(
        default_factory=ScanSummary,
        description="Aggregated severity and status summary metrics.",
    )
    mugiwara_version: str = Field(
        default="0.1.0",
        description="Version of Mugiwara Security that generated this report.",
    )

    def calculate_summary(self) -> ScanSummary:
        """Compute aggregate severity and status counts from the current findings list."""
        summary = ScanSummary(total_findings=len(self.findings))

        for finding in self.findings:
            # Severity counts
            if finding.severity == Severity.CRITICAL:
                summary.critical_count += 1
            elif finding.severity == Severity.HIGH:
                summary.high_count += 1
            elif finding.severity == Severity.MEDIUM:
                summary.medium_count += 1
            elif finding.severity == Severity.LOW:
                summary.low_count += 1
            elif finding.severity == Severity.INFO:
                summary.info_count += 1

            # Status counts
            if finding.status == FindingStatus.VERIFIED:
                summary.verified_count += 1
            elif finding.status == FindingStatus.SUSPECTED:
                summary.suspected_count += 1
            elif finding.status == FindingStatus.FALSE_POSITIVE:
                summary.false_positive_count += 1
            elif finding.status == FindingStatus.FIXED:
                summary.fixed_count += 1

        self.summary = summary
        return summary
