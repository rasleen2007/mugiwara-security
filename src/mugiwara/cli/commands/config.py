"""Implementation of the 'mugiwara config' CLI subcommands."""

from pathlib import Path
from typing import Annotated, Any

import typer
import yaml

from mugiwara.cli.console import (
    console,
    create_settings_table,
    print_error,
    print_success,
)
from mugiwara.core.config import MugiwaraSettings, load_settings
from mugiwara.core.exceptions import ConfigurationError

config_app = typer.Typer(
    name="config",
    help="View and update Mugiwara configuration settings.",
    no_args_is_help=True,
)


@config_app.command(name="show")
def show_config(
    config_file: Annotated[
        str | None,
        typer.Option(
            "--config-file",
            "-c",
            help="Path to custom YAML configuration file.",
        ),
    ] = None,
) -> None:
    """Display active configuration settings."""
    try:
        settings = load_settings(config_path=config_file)
        # model_dump converts SecretStr to masked/safe dict by default
        dumped = settings.model_dump()
        table = create_settings_table(dumped)
        console.print(table)
    except ConfigurationError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@config_app.command(name="set")
def set_config(
    key: Annotated[
        str,
        typer.Argument(
            help="Configuration key path (e.g. 'llm.model', 'scan.profile', 'log_level').",
        ),
    ],
    value: Annotated[
        str,
        typer.Argument(
            help="Value to assign to the configuration key.",
        ),
    ],
    config_file: Annotated[
        str,
        typer.Option(
            "--config-file",
            "-c",
            help="Path to YAML configuration file to update.",
        ),
    ] = "mugiwara.yaml",
) -> None:
    """Update a setting in the local YAML configuration file."""
    path = Path(config_file)
    data: dict[str, Any] = {}

    if path.is_file():
        try:
            with path.open("r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    data = loaded
        except yaml.YAMLError as exc:
            print_error(f"Failed to read existing configuration file '{path}': {exc}")
            raise typer.Exit(code=1) from exc

    # Parse nested keys e.g. "llm.model"
    parts = key.split(".")
    target = data
    for part in parts[:-1]:
        if part not in target or not isinstance(target[part], dict):
            target[part] = {}
        target = target[part]

    # Convert primitive values if appropriate (int, float, bool)
    typed_val: Any = value
    val_lower = value.lower()
    if val_lower == "true":
        typed_val = True
    elif val_lower == "false":
        typed_val = False
    elif val_lower == "null" or val_lower == "none":
        typed_val = None
    else:
        try:
            typed_val = int(value)
        except ValueError:
            try:
                typed_val = float(value)
            except ValueError:
                typed_val = value

    target[parts[-1]] = typed_val

    # Validate updated config with Pydantic
    try:
        MugiwaraSettings.model_validate(data)
    except Exception as exc:
        print_error(f"Invalid configuration value for '{key}': {exc}")
        raise typer.Exit(code=1) from exc

    # Write updated config
    try:
        with path.open("w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
        print_success(f"Updated '{key}' to '{value}' in '{path}'.")
    except Exception as exc:
        print_error(f"Failed to save configuration file '{path}': {exc}")
        raise typer.Exit(code=1) from exc
