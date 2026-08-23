"""Implementation of the 'mugiwara fix' CLI command (Phase 6 remediation)."""

import asyncio
import json
from pathlib import Path
from typing import Annotated

import typer
from rich.panel import Panel
from rich.syntax import Syntax

from mugiwara import __version__
from mugiwara.cli.commands.scan import _apply_overrides
from mugiwara.cli.console import console, print_error, print_success, print_warning
from mugiwara.core.config import (
    LLMProviderType,
    MugiwaraSettings,
    SandboxMode,
    load_settings,
)
from mugiwara.core.exceptions import ConfigurationError, MugiwaraError, ReportStoreError
from mugiwara.models.remediation import RemediationRecord, RemediationStatus
from mugiwara.remediation.service import RemediationService, build_remediation_bundle
from mugiwara.reports.store import ReportStore, resolve_report_root

_STATUS_STYLES = {
    RemediationStatus.PROPOSED: ("cyan", "PROPOSED"),
    RemediationStatus.APPLIED: ("yellow", "APPLIED"),
    RemediationStatus.VERIFIED_FIXED: ("green", "VERIFIED_FIXED — Threat Defeated"),
    RemediationStatus.NOT_FIXED: ("red", "NOT_FIXED — Patch Rejected"),
    RemediationStatus.FAILED: ("red", "FAILED — Inconclusive or Broken"),
}


def fix_command(
    target: Annotated[
        str,
        typer.Argument(
            help="Target codebase path whose verified findings should be remediated.",
        ),
    ] = ".",
    output: Annotated[
        str | None,
        typer.Option(
            "--output",
            "-o",
            help="Write a JSON fix bundle (scan + remediations) usable by 'mugiwara ui'.",
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
            help="Sandbox isolation mode override used for the post-patch sea trial.",
        ),
    ] = None,
    max_findings: Annotated[
        int,
        typer.Option(
            "--max-findings",
            help="Maximum number of verified findings to remediate in this run.",
            min=1,
        ),
    ] = 5,
    report: Annotated[
        str | None,
        typer.Option(
            "--report",
            help=(
                "Consume a persisted scan report (ID or path inside the "
                "report store) instead of scanning the target again."
            ),
        ),
    ] = None,
    project_root: Annotated[
        str | None,
        typer.Option(
            "--project-root",
            help="Explicit project root to remediate when using --report.",
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
) -> None:
    """Generate an AI patch for each verified finding, apply it to an isolated
    copy, and prove the fix by re-running the original PoC in the sandbox.

    The original working tree is never modified. Exit codes: 0 fixed/nothing
    to do, 1 operational error, 2 any patch NOT_FIXED or FAILED.
    """
    resolved_config = config_file
    if resolved_config is None and Path("mugiwara.yaml").is_file():
        resolved_config = "mugiwara.yaml"

    try:
        settings: MugiwaraSettings = load_settings(config_path=resolved_config)
    except ConfigurationError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc

    effective = _apply_overrides(
        settings,
        profile=settings.scan.profile,
        provider=provider or settings.llm.provider,
        model=model or settings.llm.model,
        sandbox_mode=sandbox or settings.sandbox.mode,
    )

    console.print(
        Panel(
            "[bold cyan]Mugiwara Shipwright[/bold cyan] — AI-assisted remediation\n"
            "[dim]Patches are applied to a disposable copy only; every fix must "
            "survive a sea trial against the original PoC.[/dim]",
            border_style="cyan",
            expand=False,
        )
    )

    service = RemediationService(effective, max_findings=max_findings)

    if report is not None:
        store_root = resolve_report_root(effective, target_path=target)
        try:
            envelope = ReportStore(store_root).load(report)
        except ReportStoreError as exc:
            print_error(f"Could not load stored report '{report}': {exc}")
            raise typer.Exit(code=1) from exc

        console.print(
            f"[dim]Consuming stored report {envelope.report_id} "
            f"(scanned {envelope.target.path}); the scanner is not run.[/dim]"
        )
        chosen_root = project_root or envelope.target.path

        try:
            result = asyncio.run(service.run_stored_report(envelope, project_root=chosen_root))
        except MugiwaraError as exc:
            print_error(f"Remediation failed: {exc}")
            raise typer.Exit(code=1) from exc
        except OSError as exc:
            print_error(f"Remediation failed due to an I/O error: {exc}")
            raise typer.Exit(code=1) from exc
    else:
        try:
            result = asyncio.run(service.run(target))
        except MugiwaraError as exc:
            print_error(f"Remediation failed: {exc}")
            raise typer.Exit(code=1) from exc
        except OSError as exc:
            print_error(f"Remediation failed due to an I/O error: {exc}")
            raise typer.Exit(code=1) from exc

    if not result.report.records:
        console.print("No dynamically verified findings to remediate.")
        for note in result.report.notes:
            print_warning(note)
        print_success("Nothing to fix. The original target was not modified.")
        return

    for record in result.report.records:
        _render_record(record)

    if output is not None:
        bundle = build_remediation_bundle(result, tool_version=__version__)
        try:
            Path(output).write_text(json.dumps(bundle, indent=2), encoding="utf-8")
            console.print(f"[green]Fix bundle written to[/green] {output}")
        except OSError as exc:
            print_error(f"Failed to write fix bundle '{output}': {exc}")
            raise typer.Exit(code=1) from exc

    unresolved = [
        record
        for record in result.report.records
        if record.status in (RemediationStatus.NOT_FIXED, RemediationStatus.FAILED)
    ]
    if unresolved:
        print_warning(
            f"{len(unresolved)} remediation(s) could not be proven fixed. "
            "The original target was never modified."
        )
        raise typer.Exit(code=2)

    print_success(
        f"{len(result.report.records)} remediation(s) processed; all patches "
        "survived their sea trials. Review diffs before applying anything."
    )


def _render_record(record: RemediationRecord) -> None:
    """Render one remediation record as the WANTED card, patch, and sea trial."""
    color, label = _STATUS_STYLES[record.status]
    cwe = record.cwe_id or "-"
    location = record.location or "-"
    console.print(
        Panel(
            f"[bold]{record.title}[/bold]\n"
            f"severity [yellow]{record.severity}[/yellow] · category "
            f"[magenta]{record.category}[/magenta] · {cwe}\n"
            f"location {location}",
            title="Verified Finding",
            border_style="red",
            expand=False,
        )
    )

    if record.unified_diff:
        console.print("[bold]Shipwright AI patch[/bold] [dim](applied to isolated copy)[/dim]")
        console.print(Syntax(record.unified_diff, "diff", theme="ansi_dark", word_wrap=True))
        if record.explanation:
            console.print(f"[italic]{record.explanation}[/italic]")

    evidence = record.post_validation_evidence
    checks: list[tuple[bool, str]] = []
    if evidence is not None:
        checks.append((True, "Patched target booted in the isolated sandbox"))
        checks.append((True, "Original PoC re-executed verbatim (same canary token)"))
        if record.status is RemediationStatus.VERIFIED_FIXED:
            checks.append((not evidence.canary_found, "Canary token no longer observed"))
            checks.append((True, "Original exploit no longer reproduces"))
        elif evidence.canary_found:
            checks.append((False, "Canary token still observed after the patch"))

    if checks:
        console.print("[bold]Sea trial[/bold]")
        for passed, text in checks:
            mark = "[green]✓[/green]" if passed else "[red]✗[/red]"
            console.print(f"  {mark} {text}")

    console.print(f"[bold {color}]Status:[/bold {color}] {label}")
    if record.reason:
        console.print(f"[dim]{record.reason}[/dim]")
    if record.status is not RemediationStatus.VERIFIED_FIXED:
        console.print("[dim]The original target remains untouched.[/dim]")
    console.print()
