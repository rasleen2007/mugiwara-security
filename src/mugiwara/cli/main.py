"""Main CLI application routing and entrypoint for Mugiwara Security."""

from typing import Annotated

import typer

from mugiwara import __version__
from mugiwara.cli.commands.config import config_app
from mugiwara.cli.commands.fix import fix_command
from mugiwara.cli.commands.init import init_command
from mugiwara.cli.commands.report import report_app
from mugiwara.cli.commands.sandbox import sandbox_app
from mugiwara.cli.commands.scan import scan_command
from mugiwara.cli.console import console

app = typer.Typer(
    name="mugiwara",
    help="Mugiwara Security — Autonomous AI-Powered Security Verification Platform.",
    no_args_is_help=True,
    add_completion=False,
)


def version_callback(value: bool) -> None:
    """Print the version string and exit."""
    if value:
        console.print(f"[bold cyan]Mugiwara Security[/bold cyan] v{__version__}")
        raise typer.Exit(code=0)


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-v",
            help="Show Mugiwara version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """Mugiwara Security command line interface."""


# Register subcommands
app.command(name="init", help="Initialize a new project configuration file.")(init_command)
app.command(name="scan", help="Execute a security scan or dry-run.")(scan_command)
app.command(name="fix", help="Generate and apply AI remediation patches.")(fix_command)

# Register command groups
app.add_typer(config_app, name="config")
app.add_typer(sandbox_app, name="sandbox")
app.add_typer(report_app, name="report")
