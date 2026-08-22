"""Implementation of the 'mugiwara report' CLI subcommands."""

from typing import Annotated

import typer

from mugiwara.cli.console import print_warning

report_app = typer.Typer(
    name="report",
    help="Inspect and export security scan reports.",
    no_args_is_help=True,
)


@report_app.command(name="show")
def report_show(
    report_id: Annotated[
        str,
        typer.Argument(help="Identifier or file path of the scan report to view."),
    ],
) -> None:
    """Display an interactive summary of a scan report."""
    msg = (
        f"Report viewing for '{report_id}' is not implemented yet "
        "and will be introduced in a future phase."
    )
    print_warning(msg)
    raise typer.Exit(code=1)


@report_app.command(name="export")
def report_export(
    report_id: Annotated[
        str,
        typer.Argument(help="Identifier or file path of the scan report to export."),
    ],
    format_opt: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Export format (e.g. sarif, json, markdown, html).",
        ),
    ] = "sarif",
    output_file: Annotated[
        str,
        typer.Option(
            "--output",
            "-o",
            help="Path to write the exported report.",
        ),
    ] = "report.sarif",
) -> None:
    """Export a scan report to SARIF, JSON, or Markdown format."""
    msg = (
        f"Report export to '{format_opt}' is not implemented yet "
        "and will be introduced in a future phase."
    )
    print_warning(msg)
    raise typer.Exit(code=1)
