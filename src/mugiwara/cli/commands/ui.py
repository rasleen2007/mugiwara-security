"""Implementation of the 'mugiwara ui' CLI command (local read-only dashboard).

Serves a single-file, zero-dependency dark dashboard that visualizes an
existing fix bundle produced by ``mugiwara fix -o``. The server binds to
127.0.0.1 only, performs no analysis, and exposes nothing beyond the supplied
report; it exists purely so results can be reviewed without leaving the host.
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Annotated, Any

import typer

from mugiwara.cli.console import console, print_error

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


def ui_command(
    report: Annotated[
        str,
        typer.Argument(help="Path to a fix bundle JSON written by 'mugiwara fix -o'."),
    ],
    port: Annotated[
        int,
        typer.Option("--port", "-p", help="Local port to serve on.", min=1, max=65535),
    ] = 8420,
) -> None:
    """Serve the local remediation dashboard for a fix bundle on 127.0.0.1."""
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
