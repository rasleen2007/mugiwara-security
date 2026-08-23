"""Unit tests for the 'mugiwara ui' dashboard command and its assets."""

import json
import threading
import urllib.request
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from mugiwara.cli.commands import ui as ui_module
from mugiwara.cli.commands.ui import (
    _INDEX_PATH,
    _REPORT_SENTINEL,
    build_handler,
    load_bundle,
    render_dashboard,
)
from mugiwara.cli.main import app

runner = CliRunner()


def _bundle() -> dict[str, Any]:
    """Return a minimal valid fix bundle."""
    return {
        "schema": "mugiwara.fix-bundle",
        "version": 1,
        "tool_version": "0.1.0",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "target_path": "/tmp/demo",
        "scan_profile": "standard",
        "pipeline_phases": ["recon", "discovery", "verification"],
        "diagnostics": {},
        "summary": {"VERIFIED_FIXED": 1, "verified_findings_total": 1},
        "findings": [
            {
                "title": "SQL injection</script><script>alert(1)</script>",
                "severity": "HIGH",
                "category": "sql_injection",
                "cwe_id": "CWE-89",
                "status": "VERIFIED",
                "location": {"file_path": "app.py", "start_line": 15},
            }
        ],
        "remediations": [],
        "notes": [],
    }


def test_dashboard_asset_exists_and_has_palette_and_sentinel() -> None:
    """The packaged single-file dashboard ships with theme + injection point."""
    assert _INDEX_PATH.is_file()
    html = _INDEX_PATH.read_text(encoding="utf-8")
    assert "#F5C542" in html
    assert "#080B12" in html
    assert _REPORT_SENTINEL in html


def test_render_dashboard_injects_and_escapes_script_breaks() -> None:
    """Injection replaces the sentinel and neutralizes '</' sequences."""
    page = render_dashboard(_bundle())
    assert _REPORT_SENTINEL not in page
    # The malicious finding title must not survive as a literal closing tag.
    assert "</script><script>alert(1)" not in page.split("window.MUGIWARA_REPORT = ", 1)[1]
    assert "<\\/script>" in page


def test_load_bundle_rejects_missing_file(tmp_path: Path) -> None:
    """Missing bundle paths fail with a clear error."""
    with pytest.raises(ValueError, match="not found"):
        load_bundle(str(tmp_path / "nope.json"))


def test_load_bundle_rejects_non_bundle_json(tmp_path: Path) -> None:
    """Arbitrary JSON documents are refused, not misinterpreted."""
    path = tmp_path / "other.json"
    path.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    with pytest.raises(ValueError, match="not a Mugiwara fix bundle"):
        load_bundle(str(path))


def test_ui_command_reports_invalid_bundle(tmp_path: Path) -> None:
    """The CLI surfaces bundle validation errors with exit code 1."""
    path = tmp_path / "bad.json"
    path.write_text("{}", encoding="utf-8")
    result = runner.invoke(app, ["ui", str(path)])
    assert result.exit_code == 1
    assert "not a Mugiwara fix bundle" in result.stdout


class _FakeServer:
    """Stand-in for ThreadingHTTPServer that records construction inputs."""

    last_instance: "_FakeServer | None" = None

    def __init__(self, addr: tuple[str, int], handler: type) -> None:
        self.addr = addr
        self.handler = handler
        self.closed = False
        _FakeServer.last_instance = self

    def serve_forever(self) -> None:
        return None

    def server_close(self) -> None:
        self.closed = True


def test_ui_command_binds_loopback_and_serves(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The command serves the rendered page on 127.0.0.1 and exits cleanly."""
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(_bundle()), encoding="utf-8")

    monkeypatch.setattr(ui_module, "ThreadingHTTPServer", _FakeServer)

    result = runner.invoke(app, ["ui", str(path), "--port", "8642"])
    assert result.exit_code == 0
    assert "http://127.0.0.1:8642/" in result.stdout

    server = _FakeServer.last_instance
    assert server is not None
    assert server.addr == ("127.0.0.1", 8642)
    assert server.closed is True


def test_dashboard_handler_serves_page_api_and_404() -> None:
    """The stdlib handler exposes the page, the JSON API, and 404s the rest."""
    bundle = _bundle()
    handler_cls = build_handler("<html>page</html>", json.dumps(bundle))
    server = ui_module.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        with urllib.request.urlopen(base + "/", timeout=5) as resp:
            assert resp.status == 200
            assert b"page" in resp.read()
        with urllib.request.urlopen(base + "/api/report", timeout=5) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            assert payload["schema"] == "mugiwara.fix-bundle"
        try:
            urllib.request.urlopen(base + "/missing", timeout=5)
            raised = False
        except Exception:
            raised = True
        assert raised
    finally:
        server.shutdown()
        server.server_close()
