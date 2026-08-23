"""Unit tests for the deterministic Markdown report exporter."""

from datetime import datetime, timezone
from typing import Any

from mugiwara.exporters.markdown import export_report_to_markdown
from mugiwara.models.evidence import Evidence, HTTPTrace
from mugiwara.models.finding import (
    Finding,
    FindingStatus,
    Severity,
    SourceLocation,
    VulnerabilityCategory,
)
from mugiwara.models.remediation import Remediation
from mugiwara.models.report import ScanReport


def _finding(**overrides: Any) -> Finding:
    values: dict[str, Any] = {
        "title": "SQL injection in user lookup",
        "description": "Untrusted username reaches cursor.execute.",
        "category": VulnerabilityCategory.SQL_INJECTION,
        "severity": Severity.HIGH,
        "status": FindingStatus.SUSPECTED,
        "cwe_id": "CWE-89",
        "location": SourceLocation(
            file_path="app/db.py",
            start_line=10,
            end_line=12,
            snippet="cursor.execute(f'SELECT * FROM users WHERE name = {u!r}')",
        ),
    }
    values.update(overrides)
    return Finding(**values)


def _report(*findings: Finding) -> ScanReport:
    # Deliberately no calculate_summary(): the renderer must not trust it.
    return ScanReport(
        target_path="D:/work/demo-app",
        scan_profile="standard",
        findings=list(findings) or [_finding()],
    )


def test_header_contains_metadata() -> None:
    document = export_report_to_markdown(_report())

    assert "# Mugiwara Security Report" in document
    assert "`D:/work/demo-app`" in document
    assert "standard" in document
    assert "Mugiwara Security v" in document


def test_summary_counts_are_computed_from_findings_not_stale_block() -> None:
    report = _report(_finding(), _finding(status=FindingStatus.VERIFIED))
    document = export_report_to_markdown(report)

    assert "| Total findings | 2 |" in document
    assert f"| Status {FindingStatus.VERIFIED.value} | 1 |" in document
    assert f"| Status {FindingStatus.SUSPECTED.value} | 1 |" in document
    assert f"| Severity {Severity.HIGH.value} | 2 |" in document
    # The untouched default summary block would have reported zeros:
    assert "| Total findings | 0 |" not in document


def test_findings_sorted_by_severity_then_input_order() -> None:
    low = _finding(title="LOW ONE", severity=Severity.LOW)
    critical = _finding(title="CRIT", severity=Severity.CRITICAL)
    high_second = _finding(title="HIGH TWO", severity=Severity.HIGH)

    document = export_report_to_markdown(_report(low, high_second, critical))

    crit_index = document.index("## Finding 1: [CRITICAL")
    high_two_index = document.index("## Finding 2: [HIGH")
    low_index = document.index("## Finding 3: [LOW")
    assert crit_index < high_two_index < low_index


def test_location_and_snippet_rendering() -> None:
    document = export_report_to_markdown(_report())

    assert "**Location:** `app/db.py:10` (lines 10-12)" in document
    assert "```python" in document
    assert "cursor.execute(f'SELECT * FROM users WHERE name = {u!r}')" in document
    assert f"[{Severity.HIGH.value} | {FindingStatus.SUSPECTED.value} | CWE-89]" in document


def test_evidence_sections_rendered() -> None:
    evidence = Evidence(
        poc_script="import requests\nprint('probe')",
        reproduction_steps=["Start app", "Send payload"],
        http_trace=HTTPTrace(
            method="GET",
            url="http://127.0.0.1:5000/users?username=CANARY",
            response_status_code=500,
            response_body_snippet="sqlite3.OperationalError",
        ),
        stdout_log="probe completed",
        canary_found=True,
        canary_token="CANARY",
        verified_at=datetime(2026, 8, 23, tzinfo=timezone.utc),
    )
    document = export_report_to_markdown(
        _report(_finding(status=FindingStatus.VERIFIED, evidence=evidence))
    )

    assert "### Verification evidence" in document
    assert "1. Start app" in document
    assert "```http" in document
    assert "GET http://127.0.0.1:5000/users?username=CANARY" in document
    assert "-> response status 500" in document
    assert "```text" in document and "probe completed" in document
    assert "**Canary observed:** yes (`CANARY`)" in document
    assert "```python" in document


def test_include_evidence_false_omits_evidence_entirely() -> None:
    evidence = Evidence(poc_script="print('probe')", canary_found=True)
    document = export_report_to_markdown(
        _report(_finding(status=FindingStatus.VERIFIED, evidence=evidence)),
        include_evidence=False,
    )

    assert "Verification evidence" not in document
    assert "print('probe')" not in document


def test_remediation_section_rendered() -> None:
    remediation = Remediation(
        explanation="Use parameterized queries instead of f-string interpolation.",
        target_file="app/db.py",
        unified_diff=(
            "--- a/app/db.py\n+++ b/app/db.py\n@@ -10 +10 @@\n"
            "-cursor.execute(...)\n+cursor.execute('... ', (u,))\n"
        ),
    )
    document = export_report_to_markdown(_report(_finding(remediation=remediation)))

    assert "### Suggested remediation" in document
    assert "parameterized queries" in document
    assert "```diff" in document
    assert "+cursor.execute('... ', (u,))" in document


def test_empty_findings_renders_placeholder_and_zero_totals() -> None:
    document = export_report_to_markdown(
        ScanReport(target_path="D:/work/demo-app", scan_profile="standard", findings=[])
    )

    assert "_No findings reported._" in document
    assert "| Total findings | 0 |" in document


def test_renderer_is_deterministic_and_does_not_mutate_input() -> None:
    finding = _finding(status=FindingStatus.VERIFIED)
    report = _report(finding)
    before = report.model_dump()

    first = export_report_to_markdown(report)
    second = export_report_to_markdown(report)

    assert first == second
    assert report.model_dump() == before
