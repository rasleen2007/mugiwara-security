"""Unit tests for the deterministic SARIF 2.1.0 exporter."""

import json
from datetime import datetime, timezone
from typing import Any

import pytest

from mugiwara.exporters.sarif import export_report_to_sarif, render_sarif
from mugiwara.models.evidence import Evidence, HTTPTrace
from mugiwara.models.finding import (
    Finding,
    FindingStatus,
    Severity,
    SourceLocation,
    VulnerabilityCategory,
)
from mugiwara.models.report import ScanReport

SNIPPET = "cursor.execute(f'SELECT * FROM users WHERE name = {username!r}')"


def _finding(**overrides: Any) -> Finding:
    values: dict[str, Any] = {
        "title": "SQL injection in user lookup",
        "description": "Untrusted username reaches cursor.execute.",
        "category": VulnerabilityCategory.SQL_INJECTION,
        "severity": Severity.HIGH,
        "status": FindingStatus.SUSPECTED,
        "location": SourceLocation(
            file_path="app/db.py",
            start_line=10,
            end_line=12,
            start_column=5,
            end_column=9,
            snippet=SNIPPET,
        ),
    }
    values.update(overrides)
    return Finding(**values)


def _report(*findings: Finding) -> ScanReport:
    return ScanReport(target_path=".", scan_profile="standard", findings=list(findings))


def _verified_evidence() -> Evidence:
    return Evidence(
        poc_script='import requests\nprint(requests.get("http://127.0.0.1:5000/users").text)',
        reproduction_steps=["Start app", "Send payload", "Observe error"],
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
        sandbox_runtime_seconds=1.25,
    )


def test_document_declares_sarif_2_1_0_schema_and_version() -> None:
    document = export_report_to_sarif(_report(_finding()))
    assert document["version"] == "2.1.0"
    assert document["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    runs = document["runs"]
    assert isinstance(runs, list) and len(runs) == 1


def test_tool_driver_metadata_present() -> None:
    from mugiwara import __version__

    driver = export_report_to_sarif(_report())["runs"][0]["tool"]["driver"]
    assert driver["name"] == "MugiwaraSecurity"
    assert driver["version"] == __version__
    assert driver["semanticVersion"] == __version__


def test_rules_generated_per_category_with_cwe_tags() -> None:
    report = _report(
        _finding(),
        _finding(
            category=VulnerabilityCategory.HARDCODED_SECRET,
            title="Hardcoded API key",
            description="API key embedded in source.",
            cwe_id="CWE-798",
        ),
    )
    rules = export_report_to_sarif(report)["runs"][0]["tool"]["driver"]["rules"]
    ids = [rule["id"] for rule in rules]
    assert ids == ["mugiwara-hardcoded-secret", "mugiwara-sql-injection"]
    secret_rule, sql_rule = rules
    assert sql_rule["name"] == "Sql Injection"
    assert "CWE-89" in sql_rule["properties"]["tags"]
    assert sql_rule["helpUri"].endswith("/89.html")
    assert "security" in secret_rule["properties"]["tags"]


@pytest.mark.parametrize(
    ("severity", "expected_level"),
    [
        (Severity.CRITICAL, "error"),
        (Severity.HIGH, "error"),
        (Severity.MEDIUM, "warning"),
        (Severity.LOW, "note"),
        (Severity.INFO, "note"),
    ],
)
def test_severity_to_sarif_level_mapping(severity: Severity, expected_level: str) -> None:
    result = export_report_to_sarif(_report(_finding(severity=severity)))["runs"][0]["results"][0]
    assert result["level"] == expected_level


def test_location_mapping_normalizes_windows_paths() -> None:
    location = SourceLocation(
        file_path="src\\app\\views.py",
        start_line=10,
        end_line=12,
        start_column=5,
        snippet=SNIPPET,
    )
    result = export_report_to_sarif(_report(_finding(location=location)))["runs"][0]["results"][0]
    physical = result["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "src/app/views.py"
    region = physical["region"]
    assert region["startLine"] == 10
    assert region["endLine"] == 12
    assert region["startColumn"] == 5
    assert region["snippet"]["text"] == SNIPPET


def test_verified_result_carries_status_and_evidence() -> None:
    finding = _finding(
        status=FindingStatus.VERIFIED,
        cvss_score=9.1,
        evidence=_verified_evidence(),
    )
    result = export_report_to_sarif(_report(finding))["runs"][0]["results"][0]
    props = result["properties"]
    assert props["mugiwara:status"] == "verified"
    assert result["message"]["text"].startswith("Verified exploitable by dynamic PoC execution.")
    assert props["security-severity"] == "9.1"
    evidence = props["mugiwara:evidence"]
    assert evidence["canaryTokenObserved"] is True
    assert evidence["canaryToken"] == "CANARY"
    assert "requests.get" in evidence["pocScript"]
    assert evidence["httpTrace"]["responseStatusCode"] == 500
    assert evidence["reproductionSteps"][0] == "Start app"
    assert evidence["verifiedAt"].startswith("2026-08-23")


def test_false_positive_findings_excluded_from_results_and_rules() -> None:
    report = _report(
        _finding(status=FindingStatus.FALSE_POSITIVE),
        _finding(),
    )
    document = export_report_to_sarif(report)
    results = document["runs"][0]["results"]
    rules = document["runs"][0]["tool"]["driver"]["rules"]
    assert len(results) == 1
    assert [rule["id"] for rule in rules] == ["mugiwara-sql-injection"]
    assert document["runs"][0]["properties"]["mugiwara:falsePositivesExcluded"] == 1


def test_suspected_result_distinguishable_from_verified() -> None:
    finding = _finding(evidence=None)
    result = export_report_to_sarif(_report(finding))["runs"][0]["results"][0]
    assert result["properties"]["mugiwara:status"] == "suspected"
    assert result["message"]["text"].startswith(
        "Suspected vulnerability that was not confirmed by dynamic verification."
    )
    assert "mugiwara:evidence" not in result["properties"]


def test_multiple_findings_sorted_deterministically() -> None:
    second = _finding(location=SourceLocation(file_path="app/db.py", start_line=3))
    first = _finding(
        category=VulnerabilityCategory.HARDCODED_SECRET,
        title="Hardcoded API key",
        description="API key embedded in source.",
        location=SourceLocation(file_path="app/config.py", start_line=2),
    )
    document = export_report_to_sarif(_report(second, first))
    uris = [
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in document["runs"][0]["results"]
    ]
    assert uris == sorted(uris)
    assert render_sarif(_report(second, first)) == render_sarif(_report(first, second))


def test_empty_report_produces_valid_empty_run() -> None:
    document = export_report_to_sarif(_report())
    run = document["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


def test_partial_fingerprints_stable_for_same_finding() -> None:
    one = export_report_to_sarif(_report(_finding()))["runs"][0]["results"][0]
    two = export_report_to_sarif(_report(_finding()))["runs"][0]["results"][0]
    assert (
        one["partialFingerprints"]["primaryLocationLineHash"]
        == two["partialFingerprints"]["primaryLocationLineHash"]
    )
    assert len(one["partialFingerprints"]["primaryLocationLineHash"]) == 64


def test_security_severity_only_emitted_with_cvss_score() -> None:
    with_cvss = export_report_to_sarif(_report(_finding(cvss_score=8.8)))
    without_cvss = export_report_to_sarif(_report(_finding()))
    assert with_cvss["runs"][0]["results"][0]["properties"]["security-severity"] == "8.8"
    assert "security-severity" not in without_cvss["runs"][0]["results"][0]["properties"]


def test_include_evidence_false_strips_evidence_properties() -> None:
    finding = _finding(status=FindingStatus.VERIFIED, evidence=_verified_evidence())
    result = export_report_to_sarif(_report(finding), include_evidence=False)["runs"][0]["results"][
        0
    ]
    assert "mugiwara:evidence" not in result["properties"]
    assert result["properties"]["mugiwara:status"] == "verified"


def test_render_sarif_roundtrip_matches_document() -> None:
    report = _report(_finding())
    rendered = render_sarif(report)
    assert json.loads(rendered) == export_report_to_sarif(report)


def test_fixed_status_represented_honestly() -> None:
    finding = _finding(status=FindingStatus.FIXED)
    result = export_report_to_sarif(_report(finding))["runs"][0]["results"][0]
    assert result["properties"]["mugiwara:status"] == "fixed"
    assert result["message"]["text"].startswith("Fixed after verification")
