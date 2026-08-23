"""Local workbench HTTP server: a thin interface over the Mugiwara engine.

The server binds to 127.0.0.1 only and exposes no analysis capability beyond
what the existing engine already performs locally. It never executes shell
commands, never touches the Docker socket directly (sandboxing happens inside
the engine), and reuses every fail-closed validation the CLI relies on:

- scan targets are validated server-side before any engine call;
- ZIP uploads are screened by :func:`mugiwara.intake.open_zip_target`;
- report references resolve through the containment-checked
  ``ReportStore`` (traversal attempts fail closed);
- remediation always binds to the exact directory stored in the report
  (``RemediationService.run_stored_report`` enforces this).
"""

import asyncio
import json
import re
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from mugiwara.core.config import MugiwaraSettings
from mugiwara.core.exceptions import MugiwaraError
from mugiwara.models.report import ScanReport
from mugiwara.reports.store import (
    ReportStore,
    ReportStoreError,
    StoredScanReport,
    resolve_report_root,
)
from mugiwara.ui.scan_runner import PipelineScanOutcome, execute_pipeline_scan

_MAX_UPLOAD_BYTES = 512 * 1024 * 1024
_UPLOAD_DIR_NAME = "mugiwara-ui-uploads"
_REPORT_ID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}-[0-9a-f]{10}(-[0-9]+)?$")
_EXPORT_FORMATS = ("json", "sarif", "markdown")


class ApiError(Exception):
    """A request-scoped failure that maps cleanly onto an HTTP error."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class ScanState:
    """Thread-safe progress record for one workbench-initiated scan."""

    scan_id: str
    target: str
    kind: str
    lock: threading.Lock = field(default_factory=threading.Lock)
    phases: list[str] = field(default_factory=list)
    phase_detail: str = ""
    status: str = "running"
    error: str | None = None
    report_id: str | None = None
    persistence_note: str | None = None
    summary: dict[str, Any] | None = None
    uploaded_archive: Path | None = None

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON-safe view of the current progress."""
        with self.lock:
            return {
                "scan_id": self.scan_id,
                "target": self.target,
                "kind": self.kind,
                "phases": list(self.phases),
                "phase_detail": self.phase_detail,
                "status": self.status,
                "error": self.error,
                "report_id": self.report_id,
                "persistence_note": self.persistence_note,
                "summary": self.summary,
            }


class Workbench:
    """State container and engine dispatcher behind the HTTP routes."""

    def __init__(self, settings: MugiwaraSettings) -> None:
        """Store effective settings and prepare empty scan bookkeeping."""
        self._settings = settings
        self._scans_lock = threading.Lock()
        self._scans: dict[str, ScanState] = {}
        self._active_lock = threading.Lock()

    @property
    def settings(self) -> MugiwaraSettings:
        """Return the settings the workbench was started with."""
        return self._settings

    @property
    def report_store(self) -> ReportStore:
        """Return the shared report store for the configured root."""
        return ReportStore(resolve_report_root(self._settings))

    # -- scans -------------------------------------------------------------

    def start_scan(
        self,
        *,
        kind: str,
        target: str | None,
        upload_bytes: bytes | None,
        upload_name: str | None,
    ) -> dict[str, Any]:
        """Validate a scan request and launch it on a worker thread.

        Returns:
            The initial scan-state snapshot.

        Raises:
            ApiError: On malformed requests, invalid targets, or when a
                scan is already running.
        """
        with self._active_lock:
            running = any(
                state.snapshot()["status"] == "running" for state in self.list_scans_state()
            )
            if running:
                raise ApiError(409, "A scan is already running. Wait for it to finish.")

            if upload_bytes is not None:
                archive = _save_upload(upload_bytes, upload_name)
                try:
                    target = _validate_zip_path(str(archive))
                except ApiError:
                    archive.unlink(missing_ok=True)
                    raise
                target = str(archive)
                kind = "zip"

            if not target or not isinstance(target, str) or not target.strip():
                raise ApiError(400, "A project directory path is required.")
            resolved_target = (
                _validate_directory_target(target)
                if kind == "directory"
                else _validate_zip_path(target)
            )

            scan_id = uuid.uuid4().hex[:12]
            state = ScanState(scan_id=scan_id, target=resolved_target, kind=kind)
            state.uploaded_archive = Path(target) if kind == "zip" else None
            with self._scans_lock:
                self._scans[scan_id] = state

        worker = threading.Thread(
            target=self._run_scan,
            args=(state,),
            name=f"mugiwara-scan-{scan_id}",
            daemon=True,
        )
        worker.start()
        return state.snapshot()

    def list_scans_state(self) -> list[ScanState]:
        """Return every tracked scan state, newest first."""
        with self._scans_lock:
            return sorted(self._scans.values(), key=lambda s: s.scan_id, reverse=True)

    def get_scan(self, scan_id: str) -> ScanState:
        """Return one scan state or raise a 404 API error."""
        with self._scans_lock:
            if scan_id not in self._scans:
                raise ApiError(404, f"Unknown scan '{scan_id}'.")
            return self._scans[scan_id]

    def _run_scan(self, state: ScanState) -> None:
        """Execute the pipeline on the worker thread and record the outcome."""

        def on_phase(phase: str, detail: str) -> None:
            """Record one secret-free orchestrator phase event."""
            with state.lock:
                state.phases.append(phase)
                state.phase_detail = detail

        try:
            outcome = execute_pipeline_scan(
                self._settings,
                state.target,
                on_phase=lambda phase, detail: on_phase(phase.value, detail),
            )
        except (MugiwaraError, OSError) as exc:
            with state.lock:
                state.status = "error"
                state.error = str(exc)
            return
        finally:
            if state.uploaded_archive is not None:
                state.uploaded_archive.unlink(missing_ok=True)

        self._record_outcome(state, outcome)

    def _record_outcome(self, state: ScanState, outcome: PipelineScanOutcome) -> None:
        """Store a finished scan's summary and persistence results."""
        report = outcome.report
        with state.lock:
            state.status = "completed"
            state.summary = _summary_view(report)
            state.persistence_note = outcome.persistence_error
            if outcome.envelope is not None:
                state.report_id = outcome.envelope.report_id

    # -- reports -----------------------------------------------------------

    def load_report(self, reference: str) -> StoredScanReport:
        """Load one stored report through the containment-checked store."""
        try:
            return self.report_store.load(reference)
        except ReportStoreError as exc:
            raise ApiError(404, str(exc)) from exc

    def delete_report(self, reference: str) -> None:
        """Delete one stored report through the store's own validation."""
        try:
            self.report_store.delete(reference)
        except ReportStoreError as exc:
            raise ApiError(404, str(exc)) from exc

    # -- fix ---------------------------------------------------------------

    def run_fix(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Generate a fix bundle from an eligible persisted report.

        The remediation service is invoked exactly like the CLI ``fix
        --report`` flow, including its fail-closed binding: the project root
        is always the directory recorded in the stored report.
        """
        reference = payload.get("report") if isinstance(payload, dict) else None
        if not isinstance(reference, str) or not reference.strip():
            raise ApiError(400, "A 'report' identifier is required.")

        envelope = self.load_report(reference)
        eligible = [finding for finding in envelope.scan.findings if finding.evidence is not None]
        if not eligible:
            raise ApiError(
                409,
                "Report has no dynamically verified findings eligible for "
                "remediation. Run a scan with verification enabled first.",
            )

        from mugiwara.remediation.service import (
            RemediationService,
            build_remediation_bundle,
        )

        service = RemediationService(self._settings.model_copy(deep=True))
        try:
            result = asyncio.run(
                service.run_stored_report(envelope, project_root=envelope.target.path)
            )
        except (MugiwaraError, OSError) as exc:
            raise ApiError(500, f"Remediation failed: {exc}") from exc
        return build_remediation_bundle(result, tool_version=_tool_version())


def _summary_view(report: ScanReport) -> dict[str, Any]:
    """Project a report onto the JSON summary shape used by the UI."""
    return {
        "total_findings": report.summary.total_findings,
        "critical_count": report.summary.critical_count,
        "high_count": report.summary.high_count,
        "medium_count": report.summary.medium_count,
        "low_count": report.summary.low_count,
        "info_count": report.summary.info_count,
        "verified_count": report.summary.verified_count,
        "suspected_count": report.summary.suspected_count,
        "false_positive_count": report.summary.false_positive_count,
    }


def _tool_version() -> str:
    """Return the running tool version for fix bundles."""
    from mugiwara import __version__

    return __version__


def _save_upload(data: bytes, name: str | None) -> Path:
    """Persist an uploaded archive under a sanitized, contained path.

    Args:
        data: Raw ZIP bytes from the browser.
        name: Client-provided file name; only its basename is kept and it
            must end with ``.zip``.

    Returns:
        The path of the saved archive inside the UI upload directory.

    Raises:
        ApiError: When the payload exceeds the size cap or the name is not a
            ZIP file name.
    """
    if len(data) > _MAX_UPLOAD_BYTES:
        raise ApiError(413, "Uploaded archive exceeds the size limit.")
    base = Path(name or "").name
    if not base.lower().endswith(".zip") or base in (".zip", ""):
        raise ApiError(400, "Only .zip archives can be uploaded.")
    safe_name = f"{uuid.uuid4().hex[:8]}-{re.sub(r'[^A-Za-z0-9._-]', '_', base)}"
    upload_root = Path(tempfile.gettempdir()) / _UPLOAD_DIR_NAME
    upload_root.mkdir(parents=True, exist_ok=True)
    destination = upload_root / safe_name
    destination.write_bytes(data)
    return destination


def _validate_directory_target(raw: str) -> str:
    """Server-side validation of a browser-supplied project directory."""
    candidate = Path(raw).expanduser().resolve()
    if not candidate.is_dir():
        raise ApiError(400, f"Target directory does not exist: {candidate}")
    if candidate.anchor == str(candidate):
        raise ApiError(400, "Filesystem roots cannot be scanned; choose a project folder.")
    return str(candidate)


def _validate_zip_path(raw: str) -> str:
    """Validate a local ZIP archive path before handing it to intake."""
    candidate = Path(raw).expanduser().resolve()
    if not candidate.is_file():
        raise ApiError(400, f"ZIP archive does not exist: {candidate}")
    if candidate.suffix.lower() != ".zip":
        raise ApiError(400, "Target must be a .zip archive.")
    return str(candidate)


def build_workbench_handler(workbench: Workbench, assets_dir: Path) -> type[BaseHTTPRequestHandler]:
    """Build the request handler exposing pages and the JSON API."""

    class WorkbenchHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib naming convention
            parsed = urlparse(self.path)
            route = parsed.path.rstrip("/") or "/"
            if route == "/":
                _serve_file(self, assets_dir / "index.html", "text/html; charset=utf-8")
            elif route == "/app.css":
                _serve_file(self, assets_dir / "app.css", "text/css; charset=utf-8")
            elif route == "/app.js":
                _serve_file(self, assets_dir / "app.js", "text/javascript; charset=utf-8")
            elif route == "/api/state":
                _send_json(self, _state_payload(workbench))
            elif route == "/api/settings":
                _send_json(self, _settings_payload(workbench.settings))
            elif route == "/api/reports":
                _send_json(self, {"reports": _reports_payload(workbench)})
            else:
                match = re.fullmatch(r"/api/reports/([^/]+)/export", route)
                if match is not None:
                    query = parse_qs(parsed.query)
                    _export_report(self, workbench, match.group(1), query)
                    return
                match = re.fullmatch(r"/api/reports/([^/]+)", route)
                if match is not None:
                    _send_json(self, _report_payload(workbench, match.group(1)))
                    return
                match = re.fullmatch(r"/api/scans/([^/]+)", route)
                if match is not None:
                    _send_json(self, workbench.get_scan(unquote(match.group(1))).snapshot())
                    return
                _send_error(self, 404, "Not found")

        def do_POST(self) -> None:  # noqa: N802 - stdlib naming convention
            route = urlparse(self.path).path.rstrip("/") or "/"
            if route == "/api/scans":
                _handle_start_scan(self, workbench)
            elif route == "/api/reports/delete":
                _handle_delete_report(self, workbench)
            elif route == "/api/fix":
                _handle_fix(self, workbench)
            else:
                _send_error(self, 404, "Not found")

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            pass  # keep the console quiet; this server is ephemeral

    return WorkbenchHandler


def _serve_file(handler: BaseHTTPRequestHandler, path: Path, content_type: str) -> None:
    """Serve a static asset, failing closed when it is missing."""
    try:
        body = path.read_bytes()
    except OSError:
        _send_error(handler, 404, "Asset unavailable.")
        return
    _respond(handler, body, content_type)


def _respond(handler: BaseHTTPRequestHandler, body: bytes, content_type: str) -> None:
    """Write a 200 response with hardened headers."""
    handler.send_response(200)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.end_headers()
    handler.wfile.write(body)


def _send_json(handler: BaseHTTPRequestHandler, payload: Any, *, status: int = 200) -> None:
    """Write one JSON document response."""
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.end_headers()
    handler.wfile.write(body)


def _send_error(handler: BaseHTTPRequestHandler, status: int, message: str) -> None:
    """Emit a JSON error document instead of the HTML default."""
    _send_json(handler, {"error": message}, status=status)


def _read_json_body(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    """Read and decode a JSON request body, raising 400 on garbage."""
    length = int(handler.headers.get("Content-Length") or 0)
    if length <= 0 or length > 1024 * 1024:
        raise ApiError(400, "Invalid request body.")
    raw = handler.rfile.read(length)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ApiError(400, "Request body must be valid JSON.") from exc
    if not isinstance(payload, dict):
        raise ApiError(400, "Request body must be a JSON object.")
    return payload


def _dispatch(handler: BaseHTTPRequestHandler, action: Any) -> None:
    """Run a route action, converting typed errors into JSON responses."""
    try:
        action()
    except ApiError as exc:
        _send_error(handler, exc.status, str(exc))
    except Exception:  # pragma: no cover - defensive: never leak tracebacks
        _send_error(handler, 500, "Internal server error.")


def _handle_start_scan(handler: BaseHTTPRequestHandler, workbench: Workbench) -> None:
    """Start a directory scan or accept an uploaded ZIP archive."""
    content_type = (handler.headers.get("Content-Type") or "").split(";")[0].strip()

    if content_type == "application/json":
        payload = _read_json_body(handler)
        _dispatch(
            handler,
            lambda: _send_json(
                handler,
                workbench.start_scan(
                    kind=str(payload.get("kind") or "directory"),
                    target=payload.get("target"),
                    upload_bytes=None,
                    upload_name=None,
                ),
            ),
        )
        return

    if content_type == "application/zip":
        length = int(handler.headers.get("Content-Length") or 0)
        if length <= 0 or length > _MAX_UPLOAD_BYTES:
            _send_error(handler, 413, "Uploaded archive exceeds the size limit.")
            return
        data = handler.rfile.read(length)
        upload_name = handler.headers.get("X-Filename") or "upload.zip"
        _dispatch(
            handler,
            lambda: _send_json(
                handler,
                workbench.start_scan(
                    kind="zip",
                    target=None,
                    upload_bytes=data,
                    upload_name=upload_name,
                ),
            ),
        )
        return

    _send_error(handler, 400, "Unsupported Content-Type.")


def _state_payload(workbench: Workbench) -> dict[str, Any]:
    """Assemble dashboard state: aggregate counts plus recent activity."""
    summaries = workbench.report_store.list_reports()
    totals = {
        "reports": len(summaries),
        "findings": sum(item.total_findings for item in summaries),
        "verified": sum(item.verified_count for item in summaries),
        "suspected": sum(item.suspected_count for item in summaries),
    }
    return {
        "totals": totals,
        "recent_reports": [item.model_dump(mode="json") for item in summaries[:5]],
        "scans": [state.snapshot() for state in workbench.list_scans_state()],
    }


def _settings_payload(settings: MugiwaraSettings) -> dict[str, Any]:
    """Project the effective configuration onto a read-only settings view."""
    return {
        "provider": settings.llm.provider.value,
        "model": settings.llm.model,
        "sandbox_mode": settings.sandbox.mode.value,
        "profile": settings.scan.profile.value,
        "verification_enabled": settings.verification.enabled,
        "include_evidence": settings.output.include_evidence,
        "reports_dir": str(resolve_report_root(settings)),
    }


def _reports_payload(workbench: Workbench) -> list[dict[str, Any]]:
    """Summarize all persisted reports through the existing store."""
    return [item.model_dump(mode="json") for item in workbench.report_store.list_reports()]


def _report_payload(workbench: Workbench, reference: str) -> dict[str, Any]:
    """Load one full stored report envelope."""
    envelope = workbench.load_report(reference)
    return envelope.model_dump(mode="json")


def _export_report(
    handler: BaseHTTPRequestHandler,
    workbench: Workbench,
    reference: str,
    query: dict[str, list[str]],
) -> None:
    """Stream a stored report as JSON, SARIF, or Markdown."""
    fmt = (query.get("format") or ["json"])[0].lower()
    if fmt not in _EXPORT_FORMATS:
        _send_error(handler, 400, "Unsupported export format.")
        return
    envelope = workbench.load_report(reference)
    include_evidence = envelope.configuration.include_evidence
    if fmt == "sarif":
        from mugiwara.exporters.sarif import export_report_to_sarif

        body = json.dumps(
            export_report_to_sarif(envelope.scan, include_evidence=include_evidence),
            indent=2,
        ).encode("utf-8")
        media = "application/sarif+json; charset=utf-8"
    elif fmt == "markdown":
        from mugiwara.exporters.markdown import export_report_to_markdown

        body = export_report_to_markdown(envelope.scan, include_evidence=include_evidence).encode(
            "utf-8"
        )
        media = "text/markdown; charset=utf-8"
    else:
        body = json.dumps(envelope.model_dump(mode="json"), indent=2).encode("utf-8")
        media = "application/json; charset=utf-8"
    filename = f"{envelope.report_id}.{fmt if fmt != 'markdown' else 'md'}"
    handler.send_response(200)
    handler.send_header("Content-Type", media)
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Content-Disposition", f'attachment; filename="{filename}"')
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.end_headers()
    handler.wfile.write(body)


def _handle_delete_report(handler: BaseHTTPRequestHandler, workbench: Workbench) -> None:
    """Delete one persisted report after store-side validation."""
    payload = _read_json_body(handler)
    reference = payload.get("report")
    if not isinstance(reference, str) or not reference.strip():
        _send_error(handler, 400, "A 'report' identifier is required.")
        return
    _dispatch(
        handler,
        lambda: _delete_and_respond(handler, workbench, reference),
    )


def _delete_and_respond(
    handler: BaseHTTPRequestHandler,
    workbench: Workbench,
    reference: str,
) -> None:
    """Perform the deletion and answer with a minimal confirmation."""
    workbench.delete_report(reference)
    _send_json(handler, {"deleted": True, "report": reference})


def _handle_fix(handler: BaseHTTPRequestHandler, workbench: Workbench) -> None:
    """Generate a fix bundle for a persisted report via the real service."""
    payload = _read_json_body(handler)
    _dispatch(handler, lambda: _send_json(handler, workbench.run_fix(payload)))


def create_workbench_server(
    settings: MugiwaraSettings,
    *,
    host: str = "127.0.0.1",
    port: int = 8420,
) -> tuple[ThreadingHTTPServer, Path]:
    """Construct the loopback-bound workbench server and its asset dir.

    Args:
        settings: Effective settings captured at startup.
        host: Bind address; only loopback values are permitted.
        port: Local port to serve on.

    Returns:
        The ready-to-start server plus the directory holding UI assets.

    Raises:
        ValueError: If a non-loopback bind address is requested.
    """
    if host not in ("127.0.0.1", "localhost"):
        msg = f"The workbench refuses non-loopback bind addresses: {host}"
        raise ValueError(msg)
    assets_dir = Path(__file__).resolve().parent / "workbench"
    handler = build_workbench_handler(Workbench(settings), assets_dir)
    server = ThreadingHTTPServer((host, port), handler)
    return server, assets_dir
