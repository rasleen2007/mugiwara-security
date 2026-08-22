"""Implementation of the 'mugiwara sandbox' CLI subcommands."""

import typer

from mugiwara.cli.console import print_warning

sandbox_app = typer.Typer(
    name="sandbox",
    help="Manage test sandbox execution environments.",
    no_args_is_help=True,
)


@sandbox_app.command(name="status")
def sandbox_status() -> None:
    """Inspect the status of local sandbox containers."""
    print_warning(
        "Sandbox management is deferred to a future phase (Sandboxed Application Execution)."
    )
    raise typer.Exit(code=1)


@sandbox_app.command(name="cleanup")
def sandbox_cleanup() -> None:
    """Clean up dangling sandbox containers, networks, and temporary volumes."""
    print_warning(
        "Sandbox cleanup is deferred to a future phase (Sandboxed Application Execution)."
    )
    raise typer.Exit(code=1)
