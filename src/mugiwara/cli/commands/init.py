"""Implementation of the 'mugiwara init' CLI command."""

from pathlib import Path
from typing import Annotated

import typer

from mugiwara.cli.console import print_error, print_success, print_warning

TEMPLATE_CONFIG = """# Mugiwara Security Configuration File
# For documentation, see docs/PROJECT_SPEC.md

log_level: INFO

llm:
  provider: openai
  model: gpt-4o
  temperature: 0.0
  max_tokens: 4096
  timeout_seconds: 60.0
  # api_key: Set via environment variable MUGIWARA_LLM__API_KEY
  # api_base: null

sandbox:
  mode: docker
  timeout_seconds: 60
  memory_limit: 2g
  cpu_quota: 2.0

scan:
  profile: standard
  target_path: .
  dry_run: false
  max_turns: 10

output:
  format: text
  output_file: null
  include_evidence: true
"""


def init_command(
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Overwrite existing mugiwara.yaml configuration file if present.",
        ),
    ] = False,
    path: Annotated[
        str,
        typer.Option(
            "--path",
            "-p",
            help="Directory or filepath where the configuration file should be created.",
        ),
    ] = "mugiwara.yaml",
) -> None:
    """Initialize a new Mugiwara Security configuration file in the project."""
    target_path = Path(path)
    if target_path.is_dir():
        target_path = target_path / "mugiwara.yaml"

    if target_path.exists() and not force:
        print_warning(
            f"Configuration file '{target_path}' already exists. Use '--force' to overwrite."
        )
        raise typer.Exit(code=0)

    try:
        target_path.write_text(TEMPLATE_CONFIG, encoding="utf-8")
        print_success(f"Initialized configuration file at '{target_path}'.")
    except Exception as exc:
        print_error(f"Failed to write configuration file '{target_path}': {exc}")
        raise typer.Exit(code=1) from exc
