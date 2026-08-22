"""Implementation of the 'mugiwara sandbox' CLI subcommands."""

from typing import Annotated

import typer
from rich.table import Table

from mugiwara.cli.console import console, print_error, print_success, print_warning
from mugiwara.sandbox import (
    DockerSandbox,
    cleanup_sandbox_resources,
    get_sandbox_status,
)

sandbox_app = typer.Typer(
    name="sandbox",
    help="Manage test sandbox execution environments.",
    no_args_is_help=True,
)


@sandbox_app.command(name="status")
def sandbox_status() -> None:
    """Inspect the status of the local sandbox backend and managed resources."""
    status = get_sandbox_status()

    table = Table(title="Mugiwara Sandbox Status", border_style="cyan")
    table.add_column("Property", style="bold white", no_wrap=True)
    table.add_column("Value", style="green")
    table.add_row("Backend", status.backend)
    table.add_row("Available", "yes" if status.available else "no")
    if status.message:
        table.add_row("Detail", status.message)
    table.add_row("Managed Containers", str(status.managed_containers))
    table.add_row("Managed Networks", str(status.managed_networks))
    console.print(table)

    if not status.available:
        print_error(
            "Docker sandbox backend is not available. "
            "Ensure the Docker daemon is installed and running."
        )
        raise typer.Exit(code=1)
    print_success("Sandbox backend is operational.")


@sandbox_app.command(name="cleanup")
def sandbox_cleanup(
    assume_yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip the confirmation prompt."),
    ] = False,
) -> None:
    """Clean up dangling Mugiwara-managed sandbox containers and networks."""
    if not DockerSandbox.is_docker_available():
        print_error(
            "Docker sandbox backend is not available. "
            "Ensure the Docker daemon is installed and running."
        )
        raise typer.Exit(code=1)

    status = get_sandbox_status()
    pending = status.managed_containers + status.managed_networks
    if pending == 0:
        print_success("No leftover Mugiwara sandbox resources found.")
        return

    if not assume_yes:
        confirm = typer.confirm(f"Remove {pending} leftover sandbox resource(s)?")
        if not confirm:
            print_warning("Cleanup aborted by user; resources left untouched.")
            return

    report = cleanup_sandbox_resources()
    for error in report.errors:
        print_error(error)
    console.print(
        f"Removed {report.containers_removed} container(s) "
        f"and {report.networks_removed} network(s)."
    )
    if report.errors:
        raise typer.Exit(code=1)
    print_success("Sandbox cleanup completed successfully.")
