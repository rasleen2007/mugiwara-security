"""Unit tests for Mugiwara Security domain data models."""

from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from mugiwara.models import (
    Evidence,
    Finding,
    FindingStatus,
    HTTPTrace,
    Remediation,
    ScanReport,
    ScanSummary,
    Severity,
    SourceLocation,
    VulnerabilityCategory,
    sanitize_headers,
)


def test_source_location_valid() -> None:
    """Verify creating a valid SourceLocation."""
    loc = SourceLocation(
        file_path="src/app/routes.py",
        start_line=42,
        end_line=45,
        start_column=5,
        end_column=30,
        snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
    )
    assert loc.file_path == "src/app/routes.py"
    assert loc.start_line == 42
    assert loc.end_line == 45
    assert loc.snippet is not None


def test_source_location_invalid_line() -> None:
    """Verify that start_line < 1 raises ValidationError."""
    invalid_payload: dict[str, object] = {"file_path": "test.py", "start_line": 0}
    with pytest.raises(ValidationError):
        SourceLocation.model_validate(invalid_payload)


def test_http_trace_sanitizes_sensitive_headers() -> None:
    """Verify that sensitive headers (Authorization, Cookie, API keys) are redacted upon init."""
    raw_headers = {
        "User-Agent": "Mugiwara-Scanner/1.0",
        "Authorization": "Bearer secret-token-12345",
        "Cookie": "session_id=abcxyz987",
        "X-Api-Key": "my-secret-key",
        "Content-Type": "application/json",
    }
    trace = HTTPTrace(
        method="POST",
        url="http://localhost:8000/api/login",
        headers=raw_headers,
        body='{"username": "admin"}',
        response_status_code=200,
        response_headers={"Set-Cookie": "auth_token=jwt12345", "Server": "uvicorn"},
        response_body_snippet='{"status": "ok"}',
    )

    assert trace.headers["User-Agent"] == "Mugiwara-Scanner/1.0"
    assert trace.headers["Content-Type"] == "application/json"
    assert trace.headers["Authorization"] == "[REDACTED]"
    assert trace.headers["Cookie"] == "[REDACTED]"
    assert trace.headers["X-Api-Key"] == "[REDACTED]"
    assert trace.response_headers["Set-Cookie"] == "[REDACTED]"
    assert trace.response_headers["Server"] == "uvicorn"


def test_sanitize_headers_helper() -> None:
    """Verify the sanitize_headers helper function directly."""
    headers = {"AUTHORIZATION": "Bearer xyz", "X-Custom": "safe"}
    sanitized = sanitize_headers(headers)
    assert sanitized["AUTHORIZATION"] == "[REDACTED]"
    assert sanitized["X-Custom"] == "safe"


def test_evidence_model() -> None:
    """Verify creating a complete Evidence model."""
    now = datetime.now(timezone.utc)
    evidence = Evidence(
        poc_script='curl -X POST http://127.0.0.1:8000/login -d "\' OR 1=1 --"',
        reproduction_steps=["1. Send crafted payload", "2. Observe admin login bypass"],
        http_trace=HTTPTrace(
            method="POST",
            url="http://127.0.0.1:8000/login",
            response_status_code=200,
        ),
        stdout_log="Admin panel accessed successfully.",
        canary_found=True,
        canary_token="canary_sqli_7f8a9",
        verified_at=now,
        sandbox_runtime_seconds=1.25,
    )
    assert evidence.canary_found is True
    assert evidence.canary_token == "canary_sqli_7f8a9"
    assert evidence.sandbox_runtime_seconds == 1.25
    assert evidence.verified_at == now


def test_remediation_model() -> None:
    """Verify creating a complete Remediation model."""
    diff = """--- a/src/app/routes.py
+++ b/src/app/routes.py
@@ -42,1 +42,1 @@
-cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
+cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
"""
    rem = Remediation(
        explanation="Use parameterized queries instead of string interpolation.",
        target_file="src/app/routes.py",
        unified_diff=diff,
        fixed_lines=(42, 43),
        is_verified_fixed=True,
        references=["https://cwe.mitre.org/data/definitions/89.html"],
    )
    assert rem.target_file == "src/app/routes.py"
    assert rem.is_verified_fixed is True
    assert len(rem.references) == 1


def test_finding_model_defaults_and_validation() -> None:
    """Verify Finding model instantiation, defaults, and field validations."""
    finding = Finding(
        title="SQL Injection in user lookup",
        description="Unsanitized user input interpolated into raw SQL query.",
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        cwe_id="CWE-89",
        cvss_score=8.5,
    )

    assert isinstance(finding.id, UUID)
    assert finding.status == FindingStatus.SUSPECTED
    assert finding.cvss_score == 8.5
    assert finding.evidence is None
    assert finding.remediation is None
    assert isinstance(finding.created_at, datetime)
    assert isinstance(finding.updated_at, datetime)


def test_finding_cvss_score_bounds() -> None:
    """Verify CVSS score must be between 0.0 and 10.0."""
    with pytest.raises(ValidationError):
        Finding(
            title="Invalid CVSS",
            description="Test",
            category=VulnerabilityCategory.OTHER,
            severity=Severity.INFO,
            cvss_score=11.0,
        )

    with pytest.raises(ValidationError):
        Finding(
            title="Invalid CVSS Negative",
            description="Test",
            category=VulnerabilityCategory.OTHER,
            severity=Severity.INFO,
            cvss_score=-1.0,
        )


def test_finding_with_nested_evidence_and_remediation() -> None:
    """Verify Finding with full nested models."""
    finding = Finding(
        id=uuid4(),
        title="Command Injection in image converter",
        description="User provided filename executed directly in shell.",
        category=VulnerabilityCategory.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        status=FindingStatus.VERIFIED,
        cwe_id="CWE-78",
        cvss_score=9.8,
        location=SourceLocation(file_path="convert.py", start_line=15),
        evidence=Evidence(canary_found=True, canary_token="canary_cmd_123"),
        remediation=Remediation(
            explanation="Use shlex.quote or avoid shell=True.",
            target_file="convert.py",
            unified_diff="--- patch",
        ),
    )

    assert finding.status == FindingStatus.VERIFIED
    assert finding.location is not None
    assert finding.location.start_line == 15
    assert finding.evidence is not None
    assert finding.evidence.canary_token == "canary_cmd_123"
    assert finding.remediation is not None
    assert finding.remediation.explanation.startswith("Use shlex.quote")


def test_finding_json_serialization_roundtrip() -> None:
    """Verify that Finding serializes to JSON and deserializes back cleanly."""
    original = Finding(
        title="Stored XSS in comments",
        description="Unescaped HTML stored in database and rendered to users.",
        category=VulnerabilityCategory.CROSS_SITE_SCRIPTING,
        severity=Severity.MEDIUM,
        status=FindingStatus.VERIFIED,
        cwe_id="CWE-79",
        location=SourceLocation(file_path="views.py", start_line=50),
        evidence=Evidence(
            http_trace=HTTPTrace(
                method="GET",
                url="http://localhost:3000/comments",
                headers={"Authorization": "Bearer token123"},
            )
        ),
    )

    json_str = original.model_dump_json()
    assert "token123" not in json_str
    assert "[REDACTED]" in json_str

    deserialized = Finding.model_validate_json(json_str)
    assert deserialized.id == original.id
    assert deserialized.title == original.title
    assert deserialized.category == VulnerabilityCategory.CROSS_SITE_SCRIPTING
    assert deserialized.severity == Severity.MEDIUM
    assert deserialized.location is not None
    assert deserialized.location.file_path == "views.py"


def test_scan_report_and_summary_calculation() -> None:
    """Verify ScanReport creation and automated summary count calculation."""
    f1 = Finding(
        title="Critical RCE",
        description="Remote code execution",
        category=VulnerabilityCategory.REMOTE_CODE_EXECUTION,
        severity=Severity.CRITICAL,
        status=FindingStatus.VERIFIED,
    )
    f2 = Finding(
        title="High SQLi",
        description="SQL injection",
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        status=FindingStatus.VERIFIED,
    )
    f3 = Finding(
        title="Medium SSRF",
        description="SSRF endpoint",
        category=VulnerabilityCategory.SERVER_SIDE_REQUEST_FORGERY,
        severity=Severity.MEDIUM,
        status=FindingStatus.SUSPECTED,
    )
    f4 = Finding(
        title="Low Header",
        description="Missing security header",
        category=VulnerabilityCategory.OTHER,
        severity=Severity.LOW,
        status=FindingStatus.FALSE_POSITIVE,
    )
    f5 = Finding(
        title="Fixed Secret",
        description="Hardcoded API key",
        category=VulnerabilityCategory.HARDCODED_SECRET,
        severity=Severity.HIGH,
        status=FindingStatus.FIXED,
    )

    report = ScanReport(
        target_path="/workspace/sample_app",
        scan_profile="deep",
        findings=[f1, f2, f3, f4, f5],
    )

    summary = report.calculate_summary()

    assert summary.total_findings == 5
    assert summary.critical_count == 1
    assert summary.high_count == 2
    assert summary.medium_count == 1
    assert summary.low_count == 1
    assert summary.info_count == 0

    assert summary.verified_count == 2
    assert summary.suspected_count == 1
    assert summary.false_positive_count == 1
    assert summary.fixed_count == 1

    # Verify JSON roundtrip of entire report
    json_report = report.model_dump_json()
    reloaded_report = ScanReport.model_validate_json(json_report)

    assert reloaded_report.id == report.id
    assert reloaded_report.summary.total_findings == 5
    assert len(reloaded_report.findings) == 5
    assert reloaded_report.findings[0].title == "Critical RCE"


def test_scan_summary_default() -> None:
    """Verify default empty ScanSummary."""
    summary = ScanSummary()
    assert summary.total_findings == 0
    assert summary.critical_count == 0
    assert summary.verified_count == 0
