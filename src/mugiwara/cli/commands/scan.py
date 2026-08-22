"""Implementation of the 'mugiwara scan' CLI command."""

from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from mugiwara.cli.console import console, print_error, print_success, print_warning
from mugiwara.core.config import (
    LLMProviderType,
    OutputFormat,
    SandboxMode,
    ScanProfile,
    load_settings,
)
from mugiwara.core.exceptions import ConfigurationError


def scan_command(
    target: Annotated[
        str,
        typer.Argument(
            help="Target codebase path or URL to analyze.",
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
) -> None:
    """Execute a security vulnerability scan against a target application."""
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

    # Non-dry run: Active scanning is not implemented in Phase 1
    print_warning(
        "Active scanning is not implemented yet and will be introduced in later phases.\n"
        "Use '--dry-run' to preview scan configuration and execution parameters."
    )
    raise typer.Exit(code=1)
