"""Deterministic SARIF 2.1.0 exporter for Mugiwara scan reports.

The emitted document is genuine SARIF (Static Analysis Results Interchange
Format) version 2.1.0 suitable for GitHub Code Scanning:

- ``FALSE_POSITIVE`` findings are excluded from results entirely.
- ``VERIFIED`` findings carry dynamic-verification evidence in result
  properties and are explicitly labelled as verified.
- Findings that were never dynamically confirmed keep their ``SUSPECTED``
  status and are explicitly labelled as unconfirmed; they are never
  presented as verified vulnerabilities.
"""

import hashlib
import json
from typing import Any

from mugiwara import __version__
from mugiwara.models.evidence import Evidence, HTTPTrace
from mugiwara.models.finding import (
    Finding,
    FindingStatus,
    Severity,
    SourceLocation,
    VulnerabilityCategory,
)
from mugiwara.models.report import ScanReport

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
_TOOL_NAME = "MugiwaraSecurity"
_MAX_LOG_CHARS = 4000
_MAX_SNIPPET_CHARS = 1000

_LEVEL_BY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_RULE_CATALOG: dict[VulnerabilityCategory, tuple[str, str, str, str | None]] = {
    VulnerabilityCategory.SQL_INJECTION: (
        "sql-injection",
        "Sql Injection",
        "Untrusted input reaches dynamic SQL construction, allowing attackers to "
        "alter query semantics.",
        "CWE-89",
    ),
    VulnerabilityCategory.COMMAND_INJECTION: (
        "command-injection",
        "Command Injection",
        "Untrusted input reaches an OS command execution sink.",
        "CWE-78",
    ),
    VulnerabilityCategory.CROSS_SITE_SCRIPTING: (
        "cross-site-scripting",
        "Cross Site Scripting",
        "Untrusted input is rendered into a web response without neutralization.",
        "CWE-79",
    ),
    VulnerabilityCategory.SERVER_SIDE_REQUEST_FORGERY: (
        "ssrf",
        "Server Side Request Forgery",
        "Untrusted input controls the destination of a server-side network request.",
        "CWE-918",
    ),
    VulnerabilityCategory.PATH_TRAVERSAL: (
        "path-traversal",
        "Path Traversal",
        "Untrusted input reaches filesystem path handling outside an intended base directory.",
        "CWE-22",
    ),
    VulnerabilityCategory.INSECURE_DIRECT_OBJECT_REFERENCE: (
        "idor",
        "Insecure Direct Object Reference",
        "Untrusted input selects a protected object without authorization checks.",
        "CWE-639",
    ),
    VulnerabilityCategory.BROKEN_AUTHENTICATION: (
        "broken-authentication",
        "Broken Authentication",
        "Authentication logic permits session impersonation or bypass.",
        "CWE-287",
    ),
    VulnerabilityCategory.SENSITIVE_DATA_EXPOSURE: (
        "sensitive-data-exposure",
        "Sensitive Data Exposure",
        "Sensitive data may be exposed through responses, logs, or storage.",
        "CWE-200",
    ),
    VulnerabilityCategory.HARDCODED_SECRET: (
        "hardcoded-secret",
        "Hardcoded Secret",
        "A credential or secret appears to be embedded directly in source code.",
        "CWE-798",
    ),
    VulnerabilityCategory.REMOTE_CODE_EXECUTION: (
        "remote-code-execution",
        "Remote Code Execution",
        "Untrusted input reaches code generation or deserialization of executable content.",
        "CWE-94",
    ),
    VulnerabilityCategory.CROSS_SITE_REQUEST_FORGERY: (
        "csrf",
        "Cross Site Request Forgery",
        "State-changing requests lack protection against cross-site forgery.",
        "CWE-352",
    ),
    VulnerabilityCategory.OTHER: (
        "other",
        "Security Weakness",
        "A security weakness reported by Mugiwara Security.",
        None,
    ),
}


def export_report_to_sarif(
    report: ScanReport,
    *,
    include_evidence: bool = True,
) -> dict[str, Any]:
    """Build a deterministic SARIF 2.1.0 log document for a scan report.

    Args:
        report: The completed scan report to serialize.
        include_evidence: Whether to embed captured verification evidence
            (PoC scripts, HTTP traces, logs) in result properties.

    Returns:
        A JSON-serializable dictionary conforming to SARIF 2.1.0. Key order
        is stable and output depends only on the report contents.
    """
    included = [f for f in report.findings if f.status is not FindingStatus.FALSE_POSITIVE]
    included.sort(key=_result_sort_key)
    rules = _build_rules(included)
    results = [_finding_to_result(f, include_evidence) for f in included]

    return {
        "$schema": _SARIF_SCHEMA_URI,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": __version__,
                        "semanticVersion": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "mugiwara:targetPath": report.target_path,
                    "mugiwara:scanProfile": report.scan_profile,
                    "mugiwara:falsePositivesExcluded": sum(
                        1 for f in report.findings if f.status is FindingStatus.FALSE_POSITIVE
                    ),
                },
            }
        ],
    }


def render_sarif(report: ScanReport, *, include_evidence: bool = True) -> str:
    """Serialize a scan report as an indented SARIF 2.1.0 JSON string."""
    return json.dumps(export_report_to_sarif(report, include_evidence=include_evidence), indent=2)


def _rule_id(category: VulnerabilityCategory) -> str:
    suffix = _RULE_CATALOG[category][0]
    return f"mugiwara-{suffix}"


def _build_rules(findings: list[Finding]) -> list[dict[str, Any]]:
    categories = sorted({f.category for f in findings}, key=_rule_id)
    rules: list[dict[str, Any]] = []
    for category in categories:
        _, name, description, default_cwe = _RULE_CATALOG[category]
        cwes = sorted({f.cwe_id for f in findings if f.category is category and f.cwe_id})
        tags = ["security", *cwes]
        if default_cwe is not None and default_cwe not in cwes:
            tags.append(default_cwe)
        rule: dict[str, Any] = {
            "id": _rule_id(category),
            "name": name,
            "shortDescription": {"text": name},
            "fullDescription": {"text": description},
            "defaultConfiguration": {"level": "warning"},
            "properties": {"tags": sorted(tags)},
        }
        primary_cwe = cwes[0] if cwes else default_cwe
        if primary_cwe is not None:
            rule["helpUri"] = (
                f"https://cwe.mitre.org/data/definitions/{primary_cwe.split('-')[1]}.html"
            )
        rules.append(rule)
    return rules


def _finding_to_result(finding: Finding, include_evidence: bool) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "mugiwara:status": finding.status.value.lower(),
        "mugiwara:category": finding.category.value,
        "mugiwara:severity": finding.severity.value,
        "mugiwara:findingId": str(finding.id),
    }
    if finding.cwe_id is not None:
        properties["cwe"] = finding.cwe_id
    if finding.cvss_score is not None:
        properties["security-severity"] = f"{finding.cvss_score:.1f}"
    if include_evidence and finding.evidence is not None:
        properties["mugiwara:evidence"] = _evidence_properties(finding.evidence)

    result: dict[str, Any] = {
        "ruleId": _rule_id(finding.category),
        "level": _LEVEL_BY_SEVERITY[finding.severity],
        "message": {"text": _message_text(finding)},
        "properties": properties,
        "partialFingerprints": {"primaryLocationLineHash": _location_fingerprint(finding)},
    }
    location_region = _physical_location(finding.location)
    if location_region is not None:
        result["locations"] = [{"physicalLocation": location_region}]
    return result


def _message_text(finding: Finding) -> str:
    summary = f"{finding.title}: {finding.description}"
    if finding.status is FindingStatus.VERIFIED:
        return f"Verified exploitable by dynamic PoC execution. {summary}"
    if finding.status is FindingStatus.FIXED:
        return f"Fixed after verification; retained for regression awareness. {summary}"
    return f"Suspected vulnerability that was not confirmed by dynamic verification. {summary}"


def _physical_location(location: SourceLocation | None) -> dict[str, Any] | None:
    if location is None:
        return None
    region: dict[str, Any] = {"startLine": location.start_line}
    if location.end_line is not None:
        region["endLine"] = location.end_line
    if location.start_column is not None:
        region["startColumn"] = location.start_column
    if location.end_column is not None:
        region["endColumn"] = location.end_column
    if location.snippet is not None:
        region["snippet"] = {"text": _truncate(location.snippet, _MAX_SNIPPET_CHARS)}
    return {
        "artifactLocation": {"uri": _to_uri(location.file_path)},
        "region": region,
    }


def _evidence_properties(evidence: Evidence) -> dict[str, Any]:
    props: dict[str, Any] = {"canaryTokenObserved": evidence.canary_found}
    if evidence.canary_token is not None:
        props["canaryToken"] = evidence.canary_token
    if evidence.poc_script is not None:
        props["pocScript"] = _truncate(evidence.poc_script, _MAX_LOG_CHARS)
    if evidence.reproduction_steps:
        props["reproductionSteps"] = list(evidence.reproduction_steps)
    if evidence.http_trace is not None:
        props["httpTrace"] = _http_trace_properties(evidence.http_trace)
    if evidence.stdout_log is not None:
        props["stdoutLog"] = _truncate(evidence.stdout_log, _MAX_LOG_CHARS)
    if evidence.stderr_log is not None:
        props["stderrLog"] = _truncate(evidence.stderr_log, _MAX_LOG_CHARS)
    if evidence.verified_at is not None:
        props["verifiedAt"] = evidence.verified_at.isoformat()
    if evidence.sandbox_runtime_seconds is not None:
        props["sandboxRuntimeSeconds"] = evidence.sandbox_runtime_seconds
    return props


def _http_trace_properties(trace: HTTPTrace) -> dict[str, Any]:
    props: dict[str, Any] = {"method": trace.method, "url": trace.url}
    if trace.response_status_code is not None:
        props["responseStatusCode"] = trace.response_status_code
    if trace.response_body_snippet is not None:
        props["responseBodySnippet"] = _truncate(trace.response_body_snippet, _MAX_SNIPPET_CHARS)
    return props


def _to_uri(file_path: str) -> str:
    normalized = file_path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "...[truncated]"


def _result_sort_key(finding: Finding) -> tuple[str, int, str]:
    path = finding.location.file_path if finding.location is not None else ""
    line = finding.location.start_line if finding.location is not None else 0
    return (path, line, _rule_id(finding.category))


def _location_fingerprint(finding: Finding) -> str:
    path = finding.location.file_path if finding.location is not None else ""
    line = finding.location.start_line if finding.location is not None else 0
    basis = f"{_rule_id(finding.category)}|{_to_uri(path)}|{line}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()
