"""Remediation and code patch models for Mugiwara Security."""

from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mugiwara.models.evidence import Evidence


class Remediation(BaseModel):
    """Represents a proposed code fix and remediation plan for a verified finding."""

    explanation: str = Field(
        min_length=1,
        description="Technical explanation of how this fix resolves the vulnerability.",
    )
    target_file: str = Field(
        min_length=1,
        description="Path to the file to be patched.",
    )
    unified_diff: str = Field(
        min_length=1,
        description="Standard unified git diff patch resolving the issue.",
    )
    fixed_lines: tuple[int, int] | None = Field(
        default=None,
        description="Start and end line numbers affected by the patch (1-indexed).",
    )
    is_verified_fixed: bool = Field(
        default=False,
        description="Whether the patch was re-tested in the sandbox against the PoC and verified.",
    )
    references: list[str] = Field(
        default_factory=list,
        description="Relevant advisory, CWE, OWASP, or documentation references.",
    )


class RemediationStatus(str, Enum):
    """Lifecycle states of one AI-assisted remediation attempt.

    ``VERIFIED_FIXED`` is only reachable after the original proof-of-concept
    was re-executed against the patched isolated copy and demonstrably no
    longer reproduces. Anything inconclusive or operationally broken is
    honestly reported as ``FAILED``, never as success.
    """

    PROPOSED = "PROPOSED"
    APPLIED = "APPLIED"
    VERIFIED_FIXED = "VERIFIED_FIXED"
    NOT_FIXED = "NOT_FIXED"
    FAILED = "FAILED"


class RemediationRecord(BaseModel):
    """Full audit trail of one remediation attempt against one verified finding.

    Category and severity carry the string values of
    :class:`~mugiwara.models.finding.VulnerabilityCategory` /
    :class:`~mugiwara.models.finding.Severity` to keep this module free of a
    model-layer import cycle.
    """

    model_config = ConfigDict(validate_assignment=True)

    id: UUID = Field(default_factory=uuid4, description="Unique identifier of this attempt.")
    finding_id: str = Field(description="String form of the remediated finding's UUID.")
    title: str = Field(min_length=1, description="Title of the remediated finding.")
    category: str = Field(min_length=1, description="Vulnerability category value.")
    severity: str = Field(min_length=1, description="Severity value.")
    cwe_id: str | None = Field(default=None, description="CWE identifier when known.")
    location: str | None = Field(
        default=None,
        description="Human-readable location of the finding ('path:line').",
    )
    status: RemediationStatus = Field(
        default=RemediationStatus.PROPOSED,
        description="Current lifecycle state of this attempt.",
    )
    explanation: str | None = Field(
        default=None,
        description="Explanation of how the proposed patch removes the vulnerability.",
    )
    file_path: str | None = Field(
        default=None,
        description="Relative path of the patched file within the target.",
    )
    original_content: str | None = Field(
        default=None,
        description="Original content of the patched file before application.",
    )
    patched_content: str | None = Field(
        default=None,
        description="Full replacement content that was applied to the isolated copy.",
    )
    unified_diff: str | None = Field(
        default=None,
        description="Unified diff between original and patched content.",
    )
    reason: str | None = Field(
        default=None,
        description="Why the attempt ended NOT_FIXED/FAILED, or a short validation note.",
    )
    original_poc_sha256: str | None = Field(
        default=None,
        description="SHA-256 of the original PoC script reused verbatim for the sea trial.",
    )
    post_validation_evidence: Evidence | None = Field(
        default=None,
        description="Evidence captured while re-running the original PoC post-patch.",
    )
    sandbox_backend: str | None = Field(
        default=None,
        description="Sandbox backend used for the sea trial, if reached.",
    )
    sandbox_session_id: str | None = Field(
        default=None,
        description="Sandbox session identifier used for the sea trial, if reached.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this attempt started (UTC).",
    )
    validated_at: datetime | None = Field(
        default=None,
        description="When the sea trial completed (UTC).",
    )

    @model_validator(mode="after")
    def validate_state_consistency(self) -> "RemediationRecord":
        """Enforce honest state/evidence invariants.

        ``VERIFIED_FIXED`` is impossible without attached post-validation
        evidence proving the canary token was NOT observed anymore, and both
        exploit-outcome states require an actual applied patch (a diff).
        """
        if self.status is RemediationStatus.VERIFIED_FIXED:
            evidence = self.post_validation_evidence
            if evidence is None:
                msg = f"{self.status.value} requires post-validation evidence."
                raise ValueError(msg)
            if evidence.canary_found:
                msg = (
                    f"{self.status.value} requires post-validation evidence "
                    "showing the canary token could NOT be observed "
                    "after the patch."
                )
                raise ValueError(msg)
            if not self.unified_diff:
                msg = f"{self.status.value} requires the applied unified diff."
                raise ValueError(msg)
        if self.status is RemediationStatus.NOT_FIXED and not self.unified_diff:
            msg = f"{self.status.value} requires the applied unified diff."
            raise ValueError(msg)
        return self


class RemediationReport(BaseModel):
    """Container for all remediation attempts made against one scan target."""

    target_path: str = Field(description="Root path of the scanned target.")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the remediation run completed (UTC).",
    )
    records: list[RemediationRecord] = Field(
        default_factory=list,
        description="One record per verified finding processed.",
    )
    notes: list[str] = Field(
        default_factory=list,
        description="Non-fatal operational notes (caps, skips, degradations).",
    )

    def status_counts(self) -> dict[str, int]:
        """Return the number of records per RemediationStatus value."""
        counts = {status.value: 0 for status in RemediationStatus}
        for record in self.records:
            counts[record.status.value] += 1
        return counts
