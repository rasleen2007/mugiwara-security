"""Unit tests for Phase 6 remediation domain models and honesty invariants."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from mugiwara.models.evidence import Evidence
from mugiwara.models.remediation import (
    RemediationRecord,
    RemediationReport,
    RemediationStatus,
)

_DIFF = "-old\n+new\n"
_CLEAN_EVIDENCE = Evidence(canary_found=False, canary_token="tok")
_DIRTY_EVIDENCE = Evidence(canary_found=True, canary_token="tok")


def _record(**overrides: object) -> RemediationRecord:
    """Build a minimal baseline record with optional field overrides."""
    fields: dict[str, object] = {
        "finding_id": "00000000-0000-0000-0000-000000000001",
        "title": "SQL injection",
        "category": "sql_injection",
        "severity": "HIGH",
    }
    fields.update(overrides)
    return RemediationRecord(**fields)  # type: ignore[arg-type]


def test_status_enum_members() -> None:
    """Verify the exact Phase 6 lifecycle state set."""
    assert {status.value for status in RemediationStatus} == {
        "PROPOSED",
        "APPLIED",
        "VERIFIED_FIXED",
        "NOT_FIXED",
        "FAILED",
    }


def test_record_defaults_and_json_roundtrip() -> None:
    """Verify a PROPOSED record serializes and deserializes losslessly."""
    record = _record()
    assert record.status is RemediationStatus.PROPOSED
    assert record.post_validation_evidence is None

    raw = record.model_dump_json()
    parsed = RemediationRecord.model_validate_json(raw)
    assert parsed.id == record.id
    assert parsed.created_at == record.created_at


def test_verified_fixed_requires_post_validation_evidence() -> None:
    """A VERIFIED_FIXED claim without evidence must be structurally impossible."""
    with pytest.raises(ValidationError, match="post-validation evidence"):
        _record(
            status=RemediationStatus.VERIFIED_FIXED,
            unified_diff=_DIFF,
        )


def test_verified_fixed_rejects_observed_canary() -> None:
    """Evidence showing the canary still echoing forbids VERIFIED_FIXED."""
    with pytest.raises(ValidationError, match="NOT be observed"):
        _record(
            status=RemediationStatus.VERIFIED_FIXED,
            unified_diff=_DIFF,
            post_validation_evidence=_DIRTY_EVIDENCE,
        )


def test_verified_fixed_requires_diff() -> None:
    """A claimed fix without an applied diff is rejected."""
    with pytest.raises(ValidationError, match="unified diff"):
        _record(
            status=RemediationStatus.VERIFIED_FIXED,
            post_validation_evidence=_CLEAN_EVIDENCE,
        )


def test_not_fixed_requires_diff() -> None:
    """A rejected patch must still carry the diff of what was attempted."""
    with pytest.raises(ValidationError, match="unified diff"):
        _record(status=RemediationStatus.NOT_FIXED)


def test_failed_allows_minimal_fields() -> None:
    """FAILED records may exist before any patch was applied."""
    record = _record(status=RemediationStatus.FAILED, reason="sandbox unavailable")
    assert record.unified_diff is None
    assert record.reason == "sandbox unavailable"


def test_assignment_revalidation_enforces_invariants() -> None:
    """Mutating into VERIFIED_FIXED without evidence re-runs the validator."""
    record = _record(unified_diff=_DIFF)
    with pytest.raises(ValidationError):
        record.status = RemediationStatus.VERIFIED_FIXED


def test_report_status_counts() -> None:
    """Verify per-status counting for CLI/UI summaries."""
    report = RemediationReport(
        target_path="/tmp/target",
        created_at=datetime.now(timezone.utc),
        records=[
            _record(
                title="a",
                status=RemediationStatus.VERIFIED_FIXED,
                unified_diff=_DIFF,
                post_validation_evidence=_CLEAN_EVIDENCE,
            ),
            _record(title="b", status=RemediationStatus.NOT_FIXED, unified_diff=_DIFF),
            _record(title="c", status=RemediationStatus.FAILED),
        ],
    )
    counts = report.status_counts()
    assert counts["VERIFIED_FIXED"] == 1
    assert counts["NOT_FIXED"] == 1
    assert counts["FAILED"] == 1
    assert counts["PROPOSED"] == 0
    assert counts["APPLIED"] == 0
