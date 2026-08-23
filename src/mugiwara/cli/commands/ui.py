"""Implementation of the 'mugiwara ui' CLI command (local dashboards).

Two modes share one loopback-only server pattern:

- **Workbench** (no argument): the primary user-facing dashboard. It can
  start scans through the existing engine, browse persisted reports, inspect
  findings, export documents, and generate sandbox-proven fix bundles. It is
  purely an interface: every security decision stays inside the engine.
- **Bundle viewer** (a fix-bundle path): the original read-only single-page
  remediation view, byte-for-byte unchanged.
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Annotated, Any

import typer

from mugiwara.cli.console import console, print_error
from mugiwara.core.config import MugiwaraSettings, load_settings

_UI_DIR = Path(__file__).resolve().parents[2] / "ui"
_INDEX_PATH = _UI_DIR / "index.html"

_REPORT_SENTINEL = "__MUGIWARA_REPORT_JSON__"


def load_bundle(path: str) -> dict[str, Any]:
    """Load and validate a fix-bundle JSON file.

    Raises:
        ValueError: If the file is missing or not a mugiwara fix bundle.
    """
    bundle_path = Path(path)
    if not bundle_path.is_file():
        msg = f"Fix bundle not found: {path}"
        raise ValueError(msg)
    try:
        payload = json.loads(bundle_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        msg = f"Fix bundle '{path}' is not valid JSON: {exc}"
        raise ValueError(msg) from exc
    if not isinstance(payload, dict) or payload.get("schema") != "mugiwara.fix-bundle":
        msg = (
            f"File '{path}' is not a Mugiwara fix bundle "
            f"(expected schema 'mugiwara.fix-bundle'). Generate one with "
            "'mugiwara fix <target> -o report.json'."
        )
        raise ValueError(msg)
    return payload


def render_dashboard(bundle: dict[str, Any]) -> str:
    """Return the dashboard HTML with the bundle injected script-safely."""
    try:
        html = _INDEX_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"Dashboard assets are missing or unreadable: {exc}"
        raise ValueError(msg) from exc
    payload = json.dumps(bundle).replace("</", "<\\/")
    if _REPORT_SENTINEL not in html:
        msg = "Dashboard template is corrupted (injection sentinel missing)."
        raise ValueError(msg)
    return html.replace(_REPORT_SENTINEL, payload)


def build_handler(page_html: str, bundle_json: str) -> type[BaseHTTPRequestHandler]:
    """Build a request handler exposing the page and the raw JSON API."""

    class DashboardHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib naming convention
            if self.path in ("/", "/index.html"):
                body = page_html.encode("utf-8")
                content_type = "text/html; charset=utf-8"
            elif self.path == "/api/report":
                body = bundle_json.encode("utf-8")
                content_type = "application/json; charset=utf-8"
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            pass  # keep the console quiet; this server is ephemeral

    return DashboardHandler


def _load_workbench_settings() -> MugiwaraSettings:
    """Load effective settings the same way the scan/fix commands do."""
    resolved_config = "mugiwara.yaml" if Path("mugiwara.yaml").is_file() else None
    return load_settings(config_path=resolved_config)


def _serve_workbench(port: int) -> None:
    """Launch the full workbench dashboard on the loopback interface."""
    from mugiwara.ui.server import create_workbench_server

    settings = _load_workbench_settings()
    try:
        server, _assets = create_workbench_server(settings, port=port)
    except (ValueError, OSError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc

    console.print(
        "[bold cyan]Mugiwara Security workbench[/bold cyan]\n"
        f"Open [link=http://127.0.0.1:{port}/]http://127.0.0.1:{port}/[/link] "
        "(Ctrl+C to stop)"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[dim]Workbench stopped.[/dim]")
    finally:
        server.server_close()


def ui_command(
    report: Annotated[
        str | None,
        typer.Argument(
            help=(
                "Optional path to a fix bundle JSON written by 'mugiwara fix -o'. "
                "Omit to launch the full workbench dashboard."
            ),
        ),
    ] = None,
    port: Annotated[
        int,
        typer.Option("--port", "-p", help="Local port to serve on.", min=1, max=65535),
    ] = 8420,
) -> None:
    """Serve the local Mugiwara dashboard on 127.0.0.1.

    Without an argument the full workbench launches: start authorized scans,
    inspect persisted reports and findings, export documents, and generate
    sandbox-proven fixes. Pass a fix-bundle path to open the classic
    single-bundle remediation view instead.
    """
    if report is None:
        _serve_workbench(port)
        return

    try:
        bundle = load_bundle(report)
        page_html = render_dashboard(bundle)
    except ValueError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc

    handler = build_handler(page_html, json.dumps(bundle))
    try:
        server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    except OSError as exc:
        print_error(f"Could not bind 127.0.0.1:{port}: {exc}")
        raise typer.Exit(code=1) from exc

    console.print(
        f"[bold cyan]Mugiwara dashboard[/bold cyan] serving [dim]{report}[/dim]\n"
        f"Open [link=http://127.0.0.1:{port}/]http://127.0.0.1:{port}/[/link] "
        "(Ctrl+C to stop)"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[dim]Dashboard stopped.[/dim]")
    finally:
        server.server_close()
