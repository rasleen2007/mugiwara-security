"""Deterministic Markdown rendering of scan reports.

The renderer is a pure function of the report: it never mutates its input,
never executes anything it renders, and computes every summary number
directly from the findings list so stale counters can never leak into
output.
"""

from mugiwara.models.finding import Finding, FindingStatus, Severity
from mugiwara.models.remediation import Remediation
from mugiwara.models.report import ScanReport

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def export_report_to_markdown(report: ScanReport, *, include_evidence: bool = True) -> str:
    """Render a complete scan report as a GitHub-flavored Markdown document.

    Args:
        report: The completed scan report to render.
        include_evidence: When False, dynamic verification evidence is
            omitted entirely.

    Returns:
        The full Markdown document as a string.
    """
    lines: list[str] = []
    _append_header(report, lines)
    _append_summary(report, lines)

    if not report.findings:
        lines.append("_No findings reported._")
        lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    ordered = sorted(
        enumerate(report.findings),
        key=lambda pair: (_SEVERITY_ORDER.get(pair[1].severity, 99), pair[0]),
    )
    for position, (_, finding) in enumerate(ordered, start=1):
        _append_finding(finding, position, include_evidence, lines)

    return "\n".join(lines).rstrip() + "\n"


def _append_header(report: ScanReport, lines: list[str]) -> None:
    """Append the document title and metadata block."""
    lines.append("# Mugiwara Security Report")
    lines.append("")
    lines.append(f"- **Target:** `{report.target_path}`")
    lines.append(f"- **Scan profile:** {report.scan_profile}")
    lines.append(f"- **Started at:** {report.started_at.isoformat()}")
    if report.completed_at is not None:
        lines.append(f"- **Completed at:** {report.completed_at.isoformat()}")
    lines.append(f"- **Generator:** Mugiwara Security v{report.mugiwara_version}")
    lines.append("")


def _append_summary(report: ScanReport, lines: list[str]) -> None:
    """Append counts computed directly from the findings list."""
    severity_counts = dict.fromkeys(Severity, 0)
    status_counts = dict.fromkeys(FindingStatus, 0)
    for finding in report.findings:
        severity_counts[finding.severity] += 1
        status_counts[finding.status] += 1

    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("| --- | ---: |")
    lines.append(f"| Total findings | {len(report.findings)} |")
    for severity in Severity:
        lines.append(f"| Severity {severity.value} | {severity_counts[severity]} |")
    for status in FindingStatus:
        lines.append(f"| Status {status.value} | {status_counts[status]} |")
    lines.append("")


def _append_finding(
    finding: Finding,
    position: int,
    include_evidence: bool,
    lines: list[str],
) -> None:
    """Render one finding with all of its available detail sections."""
    label_parts = [finding.severity.value.upper(), finding.status.value]
    if finding.cwe_id:
        label_parts.append(finding.cwe_id)
    lines.append(f"## Finding {position}: [{' | '.join(label_parts)}] {finding.title}")
    lines.append("")
    lines.append(f"**Category:** {finding.category.value}")
    lines.append("")
    lines.append(finding.description)
    lines.append("")

    if finding.location is not None:
        location = f"`{finding.location.file_path}:{finding.location.start_line}`"
        if finding.location.end_line is not None and finding.location.end_line != (
            finding.location.start_line
        ):
            location += f" (lines {finding.location.start_line}-{finding.location.end_line})"
        lines.append(f"**Location:** {location}")
        lines.append("")
        if finding.location.snippet:
            language = _snippet_language(finding.location.file_path)
            lines.append(f"```{language}")
            lines.append(finding.location.snippet)
            lines.append("```")
            lines.append("")

    if finding.cvss_score is not None or finding.cvss_vector is not None:
        cvss_parts: list[str] = []
        if finding.cvss_score is not None:
            cvss_parts.append(f"score {finding.cvss_score}")
        if finding.cvss_vector is not None:
            cvss_parts.append(f"vector `{finding.cvss_vector}`")
        lines.append(f"**CVSS:** {', '.join(cvss_parts)}")
        lines.append("")

    if finding.remediation is not None:
        _append_remediation(finding.remediation, lines)

    if include_evidence and finding.evidence is not None:
        _append_evidence(finding, lines)


def _append_remediation(remediation: Remediation, lines: list[str]) -> None:
    """Render proposed remediation guidance and patch for one finding."""
    lines.append("### Suggested remediation")
    lines.append("")
    lines.append(remediation.explanation)
    lines.append("")
    if remediation.unified_diff:
        lines.append("```diff")
        lines.append(remediation.unified_diff)
        lines.append("```")
        lines.append("")


def _append_evidence(finding: Finding, lines: list[str]) -> None:
    """Render verification evidence for one finding."""
    evidence = finding.evidence
    assert evidence is not None

    lines.append("### Verification evidence")
    lines.append("")
    if evidence.reproduction_steps:
        lines.append("**Reproduction steps:**")
        lines.append("")
        for index, step in enumerate(evidence.reproduction_steps, start=1):
            lines.append(f"{index}. {step}")
        lines.append("")
    if evidence.poc_script:
        lines.append("**Proof-of-concept script:**")
        lines.append("")
        lines.append("```python")
        lines.append(evidence.poc_script)
        lines.append("```")
        lines.append("")
    if evidence.http_trace is not None:
        trace = evidence.http_trace
        lines.append("**HTTP trace:**")
        lines.append("")
        lines.append("```http")
        lines.append(f"{trace.method} {trace.url}")
        if trace.response_status_code is not None:
            lines.append(f"-> response status {trace.response_status_code}")
        if trace.response_body_snippet:
            lines.append(trace.response_body_snippet)
        lines.append("```")
        lines.append("")
    for label, value in (
        ("stdout", evidence.stdout_log),
        ("stderr", evidence.stderr_log),
    ):
        if value:
            lines.append(f"**Sandbox {label}:**")
            lines.append("")
            lines.append("```text")
            lines.append(value)
            lines.append("```")
            lines.append("")
    lines.append(
        f"**Canary observed:** {'yes' if evidence.canary_found else 'no'}"
        + (f" (`{evidence.canary_token}`)" if evidence.canary_token else "")
    )
    lines.append("")


def _snippet_language(file_path: str) -> str:
    """Map a source file extension to a fenced-code-block language tag."""
    lowered = file_path.lower()
    for suffix, language in (
        (".py", "python"),
        (".js", "javascript"),
        (".ts", "typescript"),
        (".java", "java"),
        (".go", "go"),
        (".rb", "ruby"),
        (".php", "php"),
        (".cs", "csharp"),
        (".sql", "sql"),
    ):
        if lowered.endswith(suffix):
            return language
    return ""
