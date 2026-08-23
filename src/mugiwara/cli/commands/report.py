"""Implementation of the 'mugiwara report' CLI subcommands."""

import json
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from mugiwara.cli.commands.scan import _strip_evidence
from mugiwara.cli.console import console, print_error, print_success
from mugiwara.core.config import MugiwaraSettings, load_settings
from mugiwara.core.exceptions import ConfigurationError
from mugiwara.exporters.markdown import export_report_to_markdown
from mugiwara.exporters.sarif import export_report_to_sarif
from mugiwara.reports.store import (
    ReportStore,
    ReportStoreError,
    StoredScanReport,
    resolve_report_root,
)

report_app = typer.Typer(
    name="report",
    help="Inspect and export security scan reports.",
    no_args_is_help=True,
)

_EXPORT_SUFFIXES = {
    "json": ".json",
    "sarif": ".sarif",
    "markdown": ".md",
}


class ExportFormat(str, Enum):
    """Formats supported by 'report export'."""

    JSON = "json"
    SARIF = "sarif"
    MARKDOWN = "markdown"


@report_app.command(name="show")
def report_show(
    report_id: Annotated[
        str,
        typer.Argument(help="Identifier or file path of the scan report to view."),
    ],
    config_file: Annotated[
        str | None,
        typer.Option(
            "--config-file",
            "-c",
            help="Path to YAML configuration file.",
        ),
    ] = None,
    store: Annotated[
        str | None,
        typer.Option(
            "--store",
            help="Report store directory override (default: configured, target anchor, or CWD).",
        ),
    ] = None,
    target: Annotated[
        str | None,
        typer.Option(
            "--target",
            "-t",
            help="Project directory whose .mugiwara/reports store should be used.",
        ),
    ] = None,
) -> None:
    """Display a Markdown summary of a persisted scan report."""
    settings = _load_cli_settings(config_file)
    report_store = _open_store(store, settings, target)
    envelope = _load_report(report_store, report_id)
    typer.echo(export_report_to_markdown(envelope.scan))


@report_app.command(name="export")
def report_export(
    report_id: Annotated[
        str,
        typer.Argument(help="Identifier or file path of the scan report to export."),
    ],
    format_opt: Annotated[
        ExportFormat,
        typer.Option(
            "--format",
            "-f",
            help="Export format.",
        ),
    ] = ExportFormat.SARIF,
    output_file: Annotated[
        str | None,
        typer.Option(
            "--output",
            "-o",
            help="Path to write the exported report (default: report-<report_id><ext>).",
        ),
    ] = None,
    include_evidence: Annotated[
        bool | None,
        typer.Option(
            "--include-evidence/--no-include-evidence",
            help=(
                "Embed verification evidence in the export; defaults to the "
                "configured output.include_evidence value."
            ),
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
    store: Annotated[
        str | None,
        typer.Option(
            "--store",
            help="Report store directory override (default: configured, target anchor, or CWD).",
        ),
    ] = None,
    target: Annotated[
        str | None,
        typer.Option(
            "--target",
            "-t",
            help="Project directory whose .mugiwara/reports store should be used.",
        ),
    ] = None,
) -> None:
    """Export a persisted scan report to SARIF, JSON, or Markdown format."""
    settings = _load_cli_settings(config_file)
    report_store = _open_store(store, settings, target)
    envelope = _load_report(report_store, report_id)

    effective_include = (
        settings.output.include_evidence if include_evidence is None else include_evidence
    )
    destination = output_file or _default_export_name(envelope.report_id, format_opt)
    content = _render_export(envelope, format_opt, include_evidence=effective_include)

    try:
        destination_path = Path(destination)
        if output_file is None:
            destination_path = _unique_destination(destination_path)
        if destination_path.parent != Path(""):
            destination_path.parent.mkdir(parents=True, exist_ok=True)
        destination_path.write_text(content, encoding="utf-8")
    except OSError as exc:
        print_error(f"Failed to write export file '{destination}': {exc}")
        raise typer.Exit(code=1) from exc
    print_success(f"Exported report {envelope.report_id} to {destination_path}")


@report_app.command(name="list")
def report_list(
    config_file: Annotated[
        str | None,
        typer.Option(
            "--config-file",
            "-c",
            help="Path to YAML configuration file.",
        ),
    ] = None,
    store: Annotated[
        str | None,
        typer.Option(
            "--store",
            help="Report store directory override (default: configured, target anchor, or CWD).",
        ),
    ] = None,
    target: Annotated[
        str | None,
        typer.Option(
            "--target",
            "-t",
            help="Project directory whose .mugiwara/reports store should be used.",
        ),
    ] = None,
) -> None:
    """List persisted scan reports, newest first."""
    settings = _load_cli_settings(config_file)
    report_store = _open_store(store, settings, target)

    summaries = report_store.list_reports()
    if not summaries:
        print_success(f"No persisted reports in {report_store.root}")
        return

    table = Table(title="Persisted Scan Reports", border_style="cyan")
    table.add_column("Report ID", style="bold white")
    table.add_column("Created (UTC)", style="green")
    table.add_column("Target", max_width=48)
    table.add_column("Findings", justify="right", style="yellow")
    table.add_column("Verified", justify="right", style="green")
    table.add_column("Suspected", justify="right", style="red")

    for summary in summaries:
        table.add_row(
            summary.report_id,
            summary.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            summary.target_path,
            str(summary.total_findings),
            str(summary.verified_count),
            str(summary.suspected_count),
        )
    console.print(table)


@report_app.command(name="delete")
def report_delete(
    report_id: Annotated[
        str,
        typer.Argument(help="Identifier or file path of the scan report to delete."),
    ],
    yes: Annotated[
        bool,
        typer.Option(
            "--yes",
            "-y",
            help="Delete without asking for confirmation.",
        ),
    ] = False,
    config_file: Annotated[
        str | None,
        typer.Option(
            "--config-file",
            "-c",
            help="Path to YAML configuration file.",
        ),
    ] = None,
    store: Annotated[
        str | None,
        typer.Option(
            "--store",
            help="Report store directory override (default: configured, target anchor, or CWD).",
        ),
    ] = None,
    target: Annotated[
        str | None,
        typer.Option(
            "--target",
            "-t",
            help="Project directory whose .mugiwara/reports store should be used.",
        ),
    ] = None,
) -> None:
    """Permanently delete one persisted scan report."""
    settings = _load_cli_settings(config_file)
    report_store = _open_store(store, settings, target)

    # Validate existence and containment BEFORE prompting so traversal or
    # unknown references fail closed regardless of how confirmation goes.
    envelope = _load_report(report_store, report_id)

    if not yes:
        typer.confirm(
            f"Permanently delete report {envelope.report_id} (scanned {envelope.target.path})?",
            abort=True,
        )

    try:
        report_store.delete(envelope.report_id)
    except ReportStoreError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    print_success(f"Deleted report {envelope.report_id}")


def _default_export_name(report_id: str, export_format: ExportFormat) -> str:
    """Return the deterministic default export file name for one report."""
    return f"report-{report_id}{_EXPORT_SUFFIXES[export_format.value]}"


def _unique_destination(candidate: Path) -> Path:
    """Return a non-clobbering variant of a default export name.

    Mirrors the report store's never-overwrite semantics: when the file
    already exists, a fresh ``-2``/``-3``/... numeric suffix is chosen
    instead. Explicitly requested output paths are not routed through
    here and keep their write-through behavior.
    """
    if not candidate.exists():
        return candidate
    counter = 2
    while True:
        suffixed = candidate.with_name(f"{candidate.stem}-{counter}{candidate.suffix}")
        if not suffixed.exists():
            return suffixed
        counter += 1


def _render_export(
    envelope: StoredScanReport,
    export_format: ExportFormat,
    *,
    include_evidence: bool,
) -> str:
    """Serialize one stored report into the requested export format.

    Evidence embedding follows the same switch as scan-time exports; the
    JSON format strips evidence from the stored document the same way the
    scan command does.
    """
    if export_format is ExportFormat.JSON:
        payload = envelope
        if not include_evidence:
            payload = envelope.model_copy(deep=True)
            payload.scan = _strip_evidence(payload.scan)
        document = payload.model_dump(mode="json", by_alias=True)
        return json.dumps(document, indent=2)
    if export_format is ExportFormat.SARIF:
        return json.dumps(
            export_report_to_sarif(envelope.scan, include_evidence=include_evidence),
            indent=2,
        )
    return export_report_to_markdown(envelope.scan, include_evidence=include_evidence)


def _load_cli_settings(config_file: str | None) -> MugiwaraSettings:
    """Load settings for report commands, mirroring scan behavior."""
    resolved_config = config_file
    if resolved_config is None and Path("mugiwara.yaml").is_file():
        resolved_config = "mugiwara.yaml"
    try:
        return load_settings(config_path=resolved_config)
    except ConfigurationError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


def _open_store(
    store_override: str | None,
    settings: MugiwaraSettings,
    target: str | None = None,
) -> ReportStore:
    """Open the report store, preferring an explicit directory override.

    Without an override the shared precedence rules apply: a configured
    ``output.reports_dir`` wins, then ``<target>/.mugiwara/reports`` when
    target context is supplied, else the CWD anchor.
    """
    root = (
        Path(store_override).expanduser()
        if store_override is not None
        else resolve_report_root(settings, target)
    )
    try:
        return ReportStore(root=root)
    except OSError as exc:
        print_error(f"Cannot open report store at '{root}': {exc}")
        raise typer.Exit(code=1) from exc


def _load_report(report_store: ReportStore, reference: str) -> StoredScanReport:
    """Load one stored report, converting store errors into CLI failures."""
    try:
        return report_store.load(reference)
    except ReportStoreError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
