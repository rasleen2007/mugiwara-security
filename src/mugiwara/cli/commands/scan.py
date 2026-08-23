"""Implementation of the 'mugiwara scan' CLI command."""

import json
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from mugiwara.agents import orchestrator as orchestrator_module
from mugiwara.agents.orchestrator import SessionPhase
from mugiwara.cli.console import (
    console,
    err_console,
    print_error,
    print_phase,
    print_success,
    print_warning,
)
from mugiwara.core.config import (
    LLMProviderType,
    MugiwaraSettings,
    OutputFormat,
    SandboxMode,
    ScanProfile,
    load_settings,
)
from mugiwara.core.exceptions import (
    ArchiveRejectedError,
    ConfigurationError,
    MugiwaraError,
    ReportStoreError,
    TargetNotAvailableError,
)
from mugiwara.exporters.markdown import export_report_to_markdown
from mugiwara.exporters.sarif import export_report_to_sarif
from mugiwara.intake import open_zip_target
from mugiwara.models.finding import FindingStatus, Severity
from mugiwara.models.report import ScanReport
from mugiwara.reports.store import (
    ReportStore,
    TargetMetadata,
    resolve_report_root,
    snapshot_from_settings,
)


def scan_command(
    target: Annotated[
        str,
        typer.Argument(
            help="Target codebase directory or .zip archive to analyze.",
        ),
    ] = ".",
    profile: Annotated[
        ScanProfile | None,
        typer.Option(
            "--profile",
            "-p",
            help="Scan profile controlling agent thoroughness.",
        ),
    ] = None,
    provider: Annotated[
        LLMProviderType | None,
        typer.Option(
            "--provider",
            help="LLM provider backend override.",
        ),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option(
            "--model",
            "-m",
            help="Model identifier override.",
        ),
    ] = None,
    sandbox: Annotated[
        SandboxMode | None,
        typer.Option(
            "--sandbox",
            help="Sandbox isolation mode override.",
        ),
    ] = None,
    output: Annotated[
        str | None,
        typer.Option(
            "--output",
            "-o",
            help="Output file path for findings report.",
        ),
    ] = None,
    format_opt: Annotated[
        OutputFormat | None,
        typer.Option(
            "--format",
            help="Output reporting format.",
        ),
    ] = None,
    config_file: Annotated[
        str | None,
        typer.Option(
            "--config-file",
            "-c",
            help="Path to YAML configuration file.",
        ),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Simulate scan and display plan without executing dynamic tests or network calls.",
        ),
    ] = False,
    skip_verification: Annotated[
        bool,
        typer.Option(
            "--skip-verification",
            help="Skip dynamic PoC verification; report suspected findings only.",
        ),
    ] = False,
    no_save_report: Annotated[
        bool,
        typer.Option(
            "--no-save-report",
            help="Do not archive the scan report to the local report store.",
        ),
    ] = False,
) -> None:
    """Execute a security vulnerability scan against a target application.

    Exit codes:

    - 0: successful scan, no actionable failure.
    - 1: scan, usage, or runtime error (bad target, rejected archive,
      configuration problem, I/O failure, or internal scan failure).
    - 2: scan completed, but findings require attention (actionable
      critical/high severity findings; false positives excluded).

    Progress and diagnostics are written to stderr; stdout carries only
    machine-readable output (SARIF/Markdown documents streamed without
    ``--output``).
    """
    # Check if local config file exists if not explicitly specified
    resolved_config = config_file
    if resolved_config is None and Path("mugiwara.yaml").is_file():
        resolved_config = "mugiwara.yaml"

    try:
        settings = load_settings(config_path=resolved_config)
    except ConfigurationError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc

    # Apply CLI flag overrides to active settings
    active_profile = profile or settings.scan.profile
    active_provider = provider or settings.llm.provider
    active_model = model or settings.llm.model
    active_sandbox = sandbox or settings.sandbox.mode
    active_output_file = output or settings.output.output_file
    active_format = format_opt or settings.output.format

    if dry_run or settings.scan.dry_run:
        table = Table(title="Mugiwara Scan Plan (Dry Run)", border_style="cyan")
        table.add_column("Parameter", style="bold white")
        table.add_column("Configured Value", style="green")

        table.add_row("Target", target)
        table.add_row("Profile", active_profile.value)
        table.add_row("LLM Provider", active_provider.value)
        table.add_row("Model", active_model)
        table.add_row("Sandbox Mode", active_sandbox.value)
        table.add_row("Output Format", active_format.value)
        table.add_row("Output File", str(active_output_file))

        console.print(table)
        print_success(
            "Dry run completed successfully. No active scans or dynamic tests were executed."
        )
        return

    effective_settings = _apply_overrides(
        settings,
        profile=active_profile,
        provider=active_provider,
        model=active_model,
        sandbox_mode=active_sandbox,
    )
    if skip_verification:
        effective_settings.verification.enabled = False

    # Decorative/status output never contaminates machine-readable stdout:
    # when a SARIF/Markdown document is streamed to stdout, every table and
    # status line is routed to stderr instead.
    streams_document = active_output_file is None and active_format in (
        OutputFormat.SARIF,
        OutputFormat.MARKDOWN,
    )
    status_console = err_console if streams_document else console

    def on_phase(phase: SessionPhase, detail: str) -> None:
        """Render one deterministic orchestrator phase event."""
        print_phase(f"{_PHASE_LABELS.get(phase, phase.value)}: {detail}")

    print_phase(
        f"scan start: target={target} profile={active_profile.value} "
        f"provider={active_provider.value} sandbox={active_sandbox.value}"
    )

    archive_source: Path | None = None
    if _is_zip_target(target):
        result, archive_source = _run_zip_scanned(effective_settings, target, on_phase=on_phase)
    else:
        result = _run_orchestrator(effective_settings, target, on_phase=on_phase)

    diagnostics = result.diagnostics
    print_phase(
        f"scan complete: findings={result.report.summary.total_findings} "
        f"degraded={'yes' if diagnostics.degraded else 'no'}"
    )

    _render_summary(result, status_console=status_console)

    if not no_save_report:
        saved_at = _persist_scan_report(
            effective_settings,
            result,
            archive_source=archive_source,
        )
        if saved_at is not None:
            status_console.print(f"[green]Scan report persisted to[/green] {saved_at}")

    sarif_document: dict[str, Any] | None = None
    markdown_document: str | None = None
    if active_format is OutputFormat.SARIF:
        sarif_document = export_report_to_sarif(
            result.report,
            include_evidence=settings.output.include_evidence,
        )
    elif active_format is OutputFormat.MARKDOWN:
        markdown_document = export_report_to_markdown(
            result.report,
            include_evidence=settings.output.include_evidence,
        )

    if active_output_file is not None:
        if sarif_document is not None:
            content = json.dumps(sarif_document, indent=2)
        elif markdown_document is not None:
            content = markdown_document
        else:
            payload = (
                result.report
                if settings.output.include_evidence
                else _strip_evidence(result.report)
            )
            content = payload.model_dump_json(indent=2)
        try:
            Path(active_output_file).write_text(content, encoding="utf-8")
            console.print(f"[green]Report written to[/green] {active_output_file}")
        except OSError as exc:
            print_error(f"Failed to write report file '{active_output_file}': {exc}")
            raise typer.Exit(code=1) from exc
    elif sarif_document is not None:
        typer.echo(json.dumps(sarif_document, indent=2))
    elif markdown_document is not None:
        typer.echo(markdown_document)

    actionable = [
        finding
        for finding in result.report.findings
        if finding.status is not FindingStatus.FALSE_POSITIVE
    ]
    critical_high = sum(
        1 for finding in actionable if finding.severity in (Severity.CRITICAL, Severity.HIGH)
    )
    if critical_high > 0:
        print_warning(
            f"Scan completed with {critical_high} actionable critical/high "
            "finding(s) (false positives excluded)."
        )
        raise typer.Exit(code=2)

    print_success(
        "Scan completed cleanly. No actionable critical or high severity findings.",
        stderr=streams_document,
    )


_PHASE_LABELS: dict[SessionPhase, str] = {
    SessionPhase.VALIDATING: "target",
    SessionPhase.RECON: "recon",
    SessionPhase.DISCOVERY: "discovery",
    SessionPhase.VERIFICATION: "verification",
}


def _is_zip_target(target: str) -> bool:
    """Return True when the CLI target should be routed through ZIP intake."""
    return Path(target).suffix.lower() == ".zip"


def _run_orchestrator(
    settings: MugiwaraSettings,
    target: str,
    *,
    on_phase: Any | None = None,
) -> orchestrator_module.ScanRunResult:
    """Execute one orchestrated scan, converting failures into CLI exits."""
    try:
        return orchestrator_module.run_scan(settings, target_override=target, on_phase=on_phase)
    except MugiwaraError as exc:
        print_error(f"Scan failed: {exc}")
        raise typer.Exit(code=1) from exc
    except OSError as exc:
        print_error(f"Scan failed due to an I/O error: {exc}")
        raise typer.Exit(code=1) from exc


def _run_zip_scanned(
    settings: MugiwaraSettings,
    target: str,
    *,
    on_phase: Any | None = None,
) -> tuple[orchestrator_module.ScanRunResult, Path]:
    """Scan a .zip target through the hardened intake layer.

    The archive is validated and extracted by ``open_zip_target`` into a
    Mugiwara-owned temporary directory; the context manager guarantees the
    tree is removed whether the scan succeeds or fails. Rejections during
    validation/extraction never leave a partial tree behind.

    Args:
        settings: Effective settings for the scan.
        target: Path to the .zip archive to analyze.
        on_phase: Optional phase observer forwarded to the orchestrator.

    Returns:
        The completed scan result plus the resolved archive path.

    Raises:
        typer.Exit: If the archive is missing, malformed, unsafe, or the
            scan itself fails; the temporary extraction tree is always
            removed first.
    """
    archive_source = Path(target).expanduser().resolve()
    try:
        zip_intake = open_zip_target(target)
    except (TargetNotAvailableError, ArchiveRejectedError) as exc:
        print_error(f"ZIP target rejected: {exc}")
        raise typer.Exit(code=1) from exc

    with zip_intake as intake_target:
        result = _run_orchestrator(settings, str(intake_target.target_path), on_phase=on_phase)

    # The disposable extraction tree no longer exists, so the report is
    # bound to the durable archive location; finding locations are relative
    # paths and remain valid.
    result.report.target_path = str(archive_source)
    return result, archive_source


def _strip_evidence(report: ScanReport) -> ScanReport:
    """Return a copy of the report with dynamic evidence removed from all findings."""
    payload = report.model_copy(deep=True)
    for finding in payload.findings:
        finding.evidence = None
    return payload


def _persist_scan_report(
    settings: MugiwaraSettings,
    result: orchestrator_module.ScanRunResult,
    *,
    archive_source: Path | None = None,
) -> Path | None:
    """Archive a completed scan into the report store.

    The store root follows the shared precedence rules (configured
    ``output.reports_dir``, else ``<target>/.mugiwara/reports``). Archive
    scans never anchor the store inside their already-deleted extraction
    tree: they fall back to the configured directory or the CWD root, and
    target metadata records the source archive instead of a temporary
    path. A persistence failure never invalidates the scan itself: the
    problem is reported as a warning and the caller continues with the
    scan result.

    Args:
        settings: Effective settings the scan ran with.
        result: Completed orchestrator result to persist.
        archive_source: Resolved source archive for ZIP scans, else None.

    Returns:
        The path of the stored report document, or None when persisting
        failed or was unnecessary.
    """
    anchor = None if archive_source is not None else result.report.target_path
    origin = "archive" if archive_source is not None else "directory"
    try:
        store = ReportStore(resolve_report_root(settings, anchor))
        envelope = store.save(
            result.report,
            target=TargetMetadata(
                path=result.report.target_path,
                origin=origin,
                files_collected=result.diagnostics.files_collected,
                secret_markers_found=result.diagnostics.secret_markers_found,
            ),
            configuration=snapshot_from_settings(settings),
        )
    except (ReportStoreError, OSError) as exc:
        print_warning(f"Scan succeeded, but the report could not be persisted: {exc}")
        return None
    return store.root / f"{envelope.report_id}.json"


def _apply_overrides(
    settings: MugiwaraSettings,
    *,
    profile: ScanProfile,
    provider: LLMProviderType,
    model: str,
    sandbox_mode: SandboxMode,
) -> MugiwaraSettings:
    """Return a deep copy of settings with CLI flag overrides applied."""
    effective = settings.model_copy(deep=True)
    effective.scan.profile = profile
    effective.llm.provider = provider
    effective.llm.model = model
    effective.sandbox.mode = sandbox_mode
    return effective


def _render_summary(
    result: orchestrator_module.ScanRunResult,
    *,
    status_console: Console | None = None,
) -> None:
    """Render scan findings and operational diagnostics tables.

    Args:
        result: Completed orchestrator result.
        status_console: Console receiving the decorative tables; defaults
            to stdout. Callers streaming a machine-readable document to
            stdout pass the stderr console to keep that stream parseable.
    """
    target = status_console or console
    report = result.report
    summary = report.summary

    table = Table(title="Mugiwara Scan Summary", border_style="cyan")
    table.add_column("Metric", style="bold white")
    table.add_column("Value", justify="right", style="green")

    table.add_row("Target", report.target_path)
    table.add_row("Profile", report.scan_profile)
    table.add_row("Total Findings", str(summary.total_findings))
    table.add_row("Critical", str(summary.critical_count))
    table.add_row("High", str(summary.high_count))
    table.add_row("Medium", str(summary.medium_count))
    table.add_row("Low", str(summary.low_count))
    table.add_row("Info", str(summary.info_count))
    table.add_row("Suspected", str(summary.suspected_count))
    table.add_row("Verified", str(summary.verified_count))
    false_positives = sum(
        1 for finding in report.findings if finding.status is FindingStatus.FALSE_POSITIVE
    )
    table.add_row("False Positives", str(false_positives))
    target.print(table)

    diagnostics = result.diagnostics
    ops_table = Table(title="Session Diagnostics", border_style="blue")
    ops_table.add_column("Metric", style="bold white")
    ops_table.add_column("Value", justify="right", style="yellow")

    ops_table.add_row("Files Collected", str(diagnostics.files_collected))
    ops_table.add_row("Secret Markers (names only)", str(diagnostics.secret_markers_found))
    ops_table.add_row("Heuristic Hits", str(diagnostics.heuristic_hits))
    ops_table.add_row("LLM Calls", str(diagnostics.llm_calls))
    ops_table.add_row("Tokens Used", str(diagnostics.tokens_used))
    ops_table.add_row("Dropped References", str(diagnostics.dropped_references))
    if diagnostics.sandbox_backend is not None or diagnostics.verification_candidates > 0:
        ops_table.add_row(
            "Verification Candidates",
            str(diagnostics.verification_candidates),
        )
        ops_table.add_row("PoC Executions", str(diagnostics.verification_attempted))
        ops_table.add_row("Verified by PoC", str(diagnostics.verification_verified))
        ops_table.add_row(
            "False Positives Eliminated", str(diagnostics.verification_false_positives)
        )
        ops_table.add_row("Unverified Probes", str(diagnostics.verification_unverified))
        ops_table.add_row("Sandbox Backend", str(diagnostics.sandbox_backend or "n/a"))
        ops_table.add_row("Staging Files", str(diagnostics.staging_files))
    ops_table.add_row("Degraded", "yes" if diagnostics.degraded else "no")
    target.print(ops_table)

    for message in diagnostics.errors:
        print_warning(message)

    if report.findings:
        findings_table = Table(title="Findings", border_style="red")
        findings_table.add_column("Severity", style="bold")
        findings_table.add_column("Category")
        findings_table.add_column("Title", max_width=48)
        findings_table.add_column("Location")
        for finding in report.findings:
            location = "-"
            if finding.location is not None:
                location = f"{finding.location.file_path}:{finding.location.start_line}"
            findings_table.add_row(
                finding.severity.value,
                finding.category.value,
                finding.title[:48],
                location,
            )
        target.print(findings_table)
