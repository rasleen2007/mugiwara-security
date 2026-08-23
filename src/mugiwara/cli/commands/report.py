"""Implementation of the 'mugiwara report' CLI subcommands."""

import json
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer

from mugiwara.cli.console import print_error, print_success
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

_DEFAULT_EXPORT_NAMES = {
    "json": "report.json",
    "sarif": "report.sarif",
    "markdown": "report.md",
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
            help="Report store directory override (default: configured or CWD anchor).",
        ),
    ] = None,
) -> None:
    """Display a Markdown summary of a persisted scan report."""
    settings = _load_cli_settings(config_file)
    report_store = _open_store(store, settings)
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
            help="Path to write the exported report.",
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
            help="Report store directory override (default: configured or CWD anchor).",
        ),
    ] = None,
) -> None:
    """Export a persisted scan report to SARIF, JSON, or Markdown format."""
    settings = _load_cli_settings(config_file)
    report_store = _open_store(store, settings)
    envelope = _load_report(report_store, report_id)

    destination = output_file or _DEFAULT_EXPORT_NAMES[format_opt.value]
    content = _render_export(envelope, format_opt)

    try:
        destination_path = Path(destination)
        if destination_path.parent != Path(""):
            destination_path.parent.mkdir(parents=True, exist_ok=True)
        destination_path.write_text(content, encoding="utf-8")
    except OSError as exc:
        print_error(f"Failed to write export file '{destination}': {exc}")
        raise typer.Exit(code=1) from exc
    print_success(f"Exported report {envelope.report_id} to {destination}")


def _render_export(envelope: StoredScanReport, export_format: ExportFormat) -> str:
    """Serialize one stored report into the requested export format."""
    if export_format is ExportFormat.JSON:
        document = envelope.model_dump(mode="json", by_alias=True)
        return json.dumps(document, indent=2)
    if export_format is ExportFormat.SARIF:
        return json.dumps(export_report_to_sarif(envelope.scan), indent=2)
    return export_report_to_markdown(envelope.scan)


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


def _open_store(store_override: str | None, settings: MugiwaraSettings) -> ReportStore:
    """Open the report store, preferring an explicit directory override."""
    root = (
        Path(store_override).expanduser()
        if store_override is not None
        else resolve_report_root(settings, None)
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
