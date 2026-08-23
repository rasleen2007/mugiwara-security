"""Rich console configuration and UI display helpers for Mugiwara Security CLI."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
err_console = Console(stderr=True)


def print_banner(title: str, subtitle: str | None = None) -> None:
    """Print a styled banner panel."""
    content = f"[bold cyan]{title}[/bold cyan]"
    if subtitle:
        content += f"\n[dim]{subtitle}[/dim]"
    console.print(Panel(content, border_style="cyan", expand=False))


def print_error(message: str) -> None:
    """Print an error message to stderr."""
    err_console.print(f"[bold red]Error:[/bold red] {message}")


def print_warning(message: str) -> None:
    """Print a warning message to stderr."""
    err_console.print(f"[bold yellow]Warning:[/bold yellow] {message}")


def print_success(message: str, *, stderr: bool = False) -> None:
    """Print a success message, optionally to stderr for stream purity."""
    (err_console if stderr else console).print(f"[bold green]Success:[/bold green] {message}")


def print_phase(message: str) -> None:
    """Print one deterministic scan-phase status line to stderr.

    Phase lines carry counts and statuses only; callers must never include
    source contents, secrets, PoCs, or evidence. Output is plain styled text
    (no live regions or spinners), so it stays stable under NO_COLOR,
    non-terminal capture, and CI.
    """
    err_console.print(f"[bold cyan]phase[/bold cyan] {message}")


def create_settings_table(settings_dict: dict[str, object]) -> Table:
    """Create a formatted Rich table displaying configuration key-values."""
    table = Table(title="Mugiwara Security Configuration", border_style="cyan")
    table.add_column("Section / Key", style="bold white", no_wrap=True)
    table.add_column("Value", style="green")

    for section, values in settings_dict.items():
        if isinstance(values, dict):
            for sub_key, sub_val in values.items():
                table.add_row(f"{section}.{sub_key}", str(sub_val))
        else:
            table.add_row(section, str(values))

    return table
