"""Unit tests for the workbench UI server: routes, wiring, and security guards.

Every test drives a real ThreadingHTTPServer bound to an ephemeral 127.0.0.1
port; engine calls are faked at their seams so no Docker or network access
is ever required.
"""

import io
import json
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from mugiwara.agents.models import AgentDiagnostics
from mugiwara.agents.orchestrator import ScanRunResult, SessionPhase
from mugiwara.core.config import LLMProviderType, MugiwaraSettings, SandboxMode
from mugiwara.models.evidence import Evidence
from mugiwara.models.finding import (
    Finding,
    FindingStatus,
    Severity,
    SourceLocation,
    VulnerabilityCategory,
)
from mugiwara.models.remediation import RemediationReport
from mugiwara.models.report import ScanReport
from mugiwara.remediation.service import RemediationRunResult
from mugiwara.reports.store import (
    ReportStore,
    ScanConfigurationSnapshot,
    TargetMetadata,
)
from mugiwara.ui import scan_runner as scan_runner_module
from mugiwara.ui.server import (
    ApiError,
    _save_upload,
    create_workbench_server,
)

# ---------------------------------------------------------------- fixtures


def _settings(tmp_path: Path) -> MugiwaraSettings:
    """Return hermetic settings: mock provider, no sandbox, tmp store."""
    settings = MugiwaraSettings()
    settings.llm.provider = LLMProviderType.MOCK
    settings.sandbox.mode = SandboxMode.NONE
    settings.output.reports_dir = str(tmp_path / "reports")
    return settings


class _Server:
    """A started workbench server on an ephemeral loopback port."""

    def __init__(self, settings: MugiwaraSettings) -> None:
        self.server, _assets = create_workbench_server(settings, port=0)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def get(self, path: str) -> tuple[int, dict[str, Any] | str]:
        """Perform a GET request, returning (status, parsed body)."""
        try:
            with urllib.request.urlopen(self.base + path, timeout=10) as resp:
                return resp.status, _decode(resp)
        except urllib.error.HTTPError as exc:
            return exc.code, _decode(exc)

    def post_json(self, path: str, payload: Any) -> tuple[int, dict[str, Any]]:
        """POST a JSON document, returning (status, parsed body)."""
        request = urllib.request.Request(
            self.base + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def post_zip(self, name: str, data: bytes) -> tuple[int, dict[str, Any]]:
        """Upload raw ZIP bytes, returning (status, parsed body)."""
        request = urllib.request.Request(
            self.base + "/api/scans",
            data=data,
            headers={"Content-Type": "application/zip", "X-Filename": name},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _decode(resp: Any) -> dict[str, Any] | str:
    """Decode an HTTP response body as JSON when possible."""
    body = resp.read()
    try:
        return json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return body.decode("utf-8", errors="replace")


def _finding(
    *,
    status: FindingStatus = FindingStatus.VERIFIED,
    with_evidence: bool = True,
) -> Finding:
    """Build one representative finding."""
    return Finding(
        title="Dynamic SQL construction",
        description="User input is interpolated into a SQL statement.",
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        cwe_id="CWE-89",
        location=SourceLocation(file_path="app.py", start_line=15),
        status=status,
        evidence=(
            Evidence(
                poc_script="probe",
                canary_token="MUGIWARA_CANARY_test",
                canary_found=True,
                reproduction_steps=["step one"],
            )
            if with_evidence
            else None
        ),
    )


def _scan_report(target: str, *findings: Finding) -> ScanReport:
    """Build a calculated report for the given findings."""
    report = ScanReport(target_path=target, findings=list(findings))
    report.calculate_summary()
    report.completed_at = datetime.now(timezone.utc)
    return report


def _fake_run_scan(
    report_target: str,
    *findings: Finding,
    record_phases: bool = True,
) -> Any:
    """Create a run_scan stand-in returning a fixed result."""

    def fake(
        settings: MugiwaraSettings,
        target_override: str | None = None,
        *,
        on_phase: Any = None,
    ) -> ScanRunResult:
        if record_phases and on_phase is not None:
            for phase in (
                SessionPhase.VALIDATING,
                SessionPhase.RECON,
                SessionPhase.DISCOVERY,
            ):
                on_phase(phase, "files_collected=0")
        return ScanRunResult(
            report=_scan_report(target_override or report_target, *findings),
            diagnostics=AgentDiagnostics(),
            phases_completed=[],
        )

    return fake


def _wait_for_completion(server: "_Server", scan_id: str, timeout: float = 15.0) -> dict[str, Any]:
    """Poll a scan until it leaves the running state."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status, snapshot = server.get(f"/api/scans/{scan_id}")
        assert status == 200
        assert isinstance(snapshot, dict)
        if snapshot["status"] != "running":
            return snapshot
        time.sleep(0.05)
    raise AssertionError("scan did not finish in time")


@pytest.fixture()
def server(tmp_path: Path) -> Iterator["_Server"]:
    """Yield a started workbench server backed by a temporary store."""
    instance = _Server(_settings(tmp_path))
    yield instance
    instance.close()


# ------------------------------------------------------------ static assets


def test_workbench_assets_exist() -> None:
    """The self-contained frontend ships all three assets."""
    assets_dir = Path(__file__).resolve().parents[2] / "src" / "mugiwara" / "ui" / "workbench"
    for name in ("index.html", "app.css", "app.js"):
        assert (assets_dir / name).is_file(), name
    html = (assets_dir / "index.html").read_text(encoding="utf-8")
    for nav in ("Dashboard", "Scans", "Reports", "Findings", "Settings"):
        assert nav in html


def test_server_serves_shell_and_rejects_unknown(server: _Server) -> None:
    """GET / serves the app shell; unknown routes produce JSON 404s."""
    status, body = server.get("/")
    assert status == 200
    assert "Mugiwara" in body
    status, body = server.get("/definitely-missing")
    assert status == 404
    assert isinstance(body, dict) and "error" in body


def test_create_server_refuses_non_loopback(tmp_path: Path) -> None:
    """Non-loopback bind addresses fail closed."""
    with pytest.raises(ValueError, match="loopback"):
        create_workbench_server(_settings(tmp_path), host="0.0.0.0", port=0)


# ------------------------------------------------------------- settings/api


def test_settings_endpoint_projects_configuration(server: _Server) -> None:
    """The settings view exposes read-only effective configuration."""
    status, payload = server.get("/api/settings")
    assert status == 200
    assert isinstance(payload, dict)
    assert payload["provider"] == "mock"
    assert payload["sandbox_mode"] == "none"
    assert "reports_dir" in payload


def test_state_and_reports_endpoints_start_empty(server: _Server) -> None:
    """Fresh stores yield empty-but-well-shaped payloads."""
    status, state = server.get("/api/state")
    assert status == 200
    assert isinstance(state, dict)
    assert state["totals"]["reports"] == 0
    status, reports = server.get("/api/reports")
    assert status == 200
    assert reports == {"reports": []}


# ------------------------------------------------------------- scan wiring


def test_directory_scan_runs_engine_and_persists(
    server: _Server,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The full browser workflow reaches the engine and the report store."""
    project = tmp_path / "proj"
    project.mkdir()
    monkeypatch.setattr(
        scan_runner_module,
        "run_scan",
        _fake_run_scan(str(project), _finding()),
    )

    status, started = server.post_json("/api/scans", {"kind": "directory", "target": str(project)})
    assert status == 200
    final = _wait_for_completion(server, started["scan_id"])

    assert final["status"] == "completed"
    assert final["error"] is None
    assert "recon" in final["phases"]
    assert final["summary"]["total_findings"] == 1
    assert final["report_id"] is not None

    store = ReportStore(tmp_path / "reports")
    envelope = store.load(final["report_id"])
    assert envelope.scan.target_path == str(project)
    assert envelope.target.origin == "directory"


def test_scan_request_validation_rejects_bad_targets(server: _Server) -> None:
    """Malformed or nonexistent targets are rejected before any engine call."""
    status, body = server.post_json("/api/scans", {"kind": "directory"})
    assert status == 400
    assert "required" in body["error"]

    status, body = server.post_json(
        "/api/scans", {"kind": "directory", "target": "Z:/does/not/exist"}
    )
    assert status == 400

    status, body = server.post_json("/api/scans", {"kind": "zip", "target": "Z:/nope.zip"})
    assert status == 400


@pytest.mark.parametrize("root", ["/", "C:\\"])
def test_filesystem_roots_rejected(server: _Server, root: str) -> None:
    """Filesystem roots are refused as scan targets."""
    status, body = server.post_json("/api/scans", {"kind": "directory", "target": root})
    assert status == 400
    assert "roots cannot be scanned" in body["error"]


def test_second_scan_rejected_while_running(
    server: _Server,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only one scan may run at a time."""
    project = tmp_path / "proj"
    project.mkdir()
    release = threading.Event()

    def blocking_run(
        settings: MugiwaraSettings, target_override: str | None = None, *, on_phase: Any = None
    ) -> Any:
        release.wait(timeout=10)
        return _fake_run_scan(str(project), record_phases=False)(settings, target_override)

    monkeypatch.setattr(scan_runner_module, "run_scan", blocking_run)

    status, first = server.post_json("/api/scans", {"kind": "directory", "target": str(project)})
    assert status == 200
    status, second = server.post_json("/api/scans", {"kind": "directory", "target": str(project)})
    assert status == 409
    assert "already running" in second["error"]

    release.set()
    _wait_for_completion(server, first["scan_id"])


def test_zip_upload_flow_routes_through_intake(
    server: _Server,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Uploaded archives are saved, validated, scanned, and cleaned up."""
    captured: dict[str, str] = {}

    def capturing_run(
        settings: MugiwaraSettings, target_override: str | None = None, *, on_phase: Any = None
    ) -> Any:
        captured["target"] = target_override or ""
        return _fake_run_scan(target_override or "", record_phases=False)(settings, target_override)

    monkeypatch.setattr(scan_runner_module, "run_scan", capturing_run)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("app/main.py", "print('hi')\n")
    status, started = server.post_zip("demo-app.zip", buffer.getvalue())
    assert status == 200

    final = _wait_for_completion(server, started["scan_id"])
    assert final["status"] == "completed"
    assert final["kind"] == "zip"
    # The scanned target was inside the disposable intake tree.
    assert captured["target"].endswith(".zip") is False
    assert ".zip" not in Path(captured["target"]).name
    upload_dir = Path(tempfile.gettempdir()) / "mugiwara-ui-uploads"
    assert list(upload_dir.glob("*")) == []

    # ZIP scans anchor the store outside the deleted tree.
    assert final["report_id"] is not None
    store = ReportStore(tmp_path / "reports")
    envelope = store.load(final["report_id"])
    assert envelope.target.origin == "archive"


def test_upload_validation_rejects_non_zip_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Upload names must be real .zip basenames; oversized payloads fail."""
    import mugiwara.ui.server as server_module

    monkeypatch.setattr(server_module, "_MAX_UPLOAD_BYTES", 16)
    with pytest.raises(ApiError, match=r"\.zip"):
        _save_upload(b"data", "payload.txt")
    with pytest.raises(ApiError, match="size limit"):
        _save_upload(b"x" * 32, "huge.zip")


def test_real_engine_scan_completes_via_workbench(
    server: "_Server",
    tmp_path: Path,
) -> None:
    """A genuine engine scan (mock provider, sandbox off) runs unmodified."""
    project = tmp_path / "real"
    project.mkdir()
    (project / "app.py").write_text(
        "def query(uid):\n    return 'SELECT * FROM users WHERE id = %s' % uid\n",
        encoding="utf-8",
    )

    status, started = server.post_json("/api/scans", {"kind": "directory", "target": str(project)})
    assert status == 200
    final = _wait_for_completion(server, started["scan_id"], timeout=60)
    assert final["status"] == "completed", final
    assert final["error"] is None
    assert final["report_id"] is not None
    assert final["summary"] is not None

    store = ReportStore(tmp_path / "reports")
    envelope = store.load(final["report_id"])
    assert envelope.scan.target_path == str(project.resolve())


# ------------------------------------------------------------------ reports


def _seed_report(tmp_path: Path, target: Path, finding: Finding) -> str:
    """Persist one report into the workbench store and return its ID."""
    settings = _settings(tmp_path)
    reports_dir = settings.output.reports_dir
    assert reports_dir is not None
    store = ReportStore(reports_dir)
    report = _scan_report(str(target), finding)
    envelope = store.save(
        report,
        target=TargetMetadata(path=str(target), origin="directory"),
        configuration=ScanConfigurationSnapshot(
            scan_profile="standard",
            llm_provider="mock",
            llm_model="gpt-4o",
            sandbox_mode="none",
            verification_enabled=True,
            include_evidence=True,
        ),
    )
    return envelope.report_id


def test_report_detail_listing_and_delete(
    server: _Server,
    tmp_path: Path,
) -> None:
    """Reports flow through the containment-checked store end to end."""
    project = tmp_path / "seeded"
    project.mkdir()
    report_id = _seed_report(
        tmp_path, project, _finding(status=FindingStatus.SUSPECTED, with_evidence=False)
    )

    status, listing = server.get("/api/reports")
    assert status == 200
    assert isinstance(listing, dict)
    assert [item["report_id"] for item in listing["reports"]] == [report_id]

    status, detail = server.get(f"/api/reports/{report_id}")
    assert status == 200
    assert isinstance(detail, dict)
    assert detail["schema_name"] == "mugiwara.scan-report"
    assert detail["scan"]["target_path"] == str(project)

    status, deleted = server.post_json("/api/reports/delete", {"report": report_id})
    assert status == 200
    assert deleted["deleted"] is True
    status, listing = server.get("/api/reports")
    assert isinstance(listing, dict)
    assert listing["reports"] == []


def test_report_traversal_reference_fails_closed(server: _Server, tmp_path: Path) -> None:
    """Path traversal via report references never escapes the store."""
    secret = tmp_path / "secret.json"
    secret.write_text("{}", encoding="utf-8")

    status, body = server.post_json(
        "/api/reports/delete",
        {"report": str(secret)},
    )
    assert status == 404
    assert "escapes the report store" in body["error"]

    status, body = server.post_json("/api/reports/delete", {"report": "../../escape"})
    assert status == 404


def test_export_formats(
    server: _Server,
    tmp_path: Path,
) -> None:
    """JSON/SARIF/Markdown exports reuse the existing exporters."""
    project = tmp_path / "exported"
    project.mkdir()
    report_id = _seed_report(tmp_path, project, _finding())

    status, body = server.get(f"/api/reports/{report_id}/export?format=json")
    assert status == 200
    assert isinstance(body, dict) and body["schema_name"] == "mugiwara.scan-report"

    status, sarif_payload = server.get(f"/api/reports/{report_id}/export?format=sarif")
    assert status == 200
    assert isinstance(sarif_payload, dict)
    assert sarif_payload["version"] == "2.1.0"
    assert "runs" in sarif_payload

    status, markdown_text = server.get(f"/api/reports/{report_id}/export?format=markdown")
    assert status == 200
    assert isinstance(markdown_text, str)
    assert markdown_text.startswith("# Mugiwara Security Report")

    status, body = server.get(f"/api/reports/{report_id}/export?format=exe")
    assert status == 400


# ---------------------------------------------------------------------- fix


def test_fix_action_uses_existing_service_with_fail_closed_binding(
    server: "_Server",
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fix generation reuses RemediationService and binds to the stored root."""
    project = tmp_path / "fixable"
    project.mkdir()
    report_id = _seed_report(tmp_path, project, _finding())

    captured: dict[str, str] = {}

    async def fake_run_stored(self: Any, stored: Any, *, project_root: str) -> RemediationRunResult:
        captured["root"] = str(project_root)
        captured["stored_root"] = stored.target.path
        return RemediationRunResult(
            report=RemediationReport(target_path=str(project_root), notes=[]),
            scan=ScanRunResult(
                report=stored.scan,
                diagnostics=AgentDiagnostics(),
                phases_completed=[],
            ),
        )

    monkeypatch.setattr(
        "mugiwara.remediation.service.RemediationService.run_stored_report",
        fake_run_stored,
    )

    status, bundle = server.post_json("/api/fix", {"report": report_id})
    assert status == 200
    assert bundle["schema"] == "mugiwara.fix-bundle"
    # Fail-closed binding preserved: exactly the directory recorded in the report.
    assert captured["root"] == captured["stored_root"]
    assert Path(captured["root"]) == project.resolve()


def test_fix_rejects_reports_without_verified_findings(
    server: _Server,
    tmp_path: Path,
) -> None:
    """Reports without eligible verified findings refuse fix generation."""
    project = tmp_path / "unverified"
    project.mkdir()
    report_id = _seed_report(
        tmp_path,
        project,
        _finding(status=FindingStatus.FALSE_POSITIVE, with_evidence=False),
    )
    status, body = server.post_json("/api/fix", {"report": report_id})
    assert status == 409
    assert "eligible" in body["error"]


def test_fix_eligibility_cannot_be_forced_by_client_payload(
    server: "_Server",
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The frontend can only send a report reference; the server recomputes
    eligibility from stored findings, so suspected findings can never be
    smuggled through with extra payload fields."""
    project = tmp_path / "forced"
    project.mkdir()
    report_id = _seed_report(
        tmp_path,
        project,
        _finding(status=FindingStatus.SUSPECTED, with_evidence=False),
    )

    def explode(self: Any, stored: Any, *, project_root: str) -> RemediationRunResult:
        raise AssertionError("remediation service must not run for ineligible reports")

    monkeypatch.setattr(
        "mugiwara.remediation.service.RemediationService.run_stored_report",
        explode,
    )

    status, body = server.post_json(
        "/api/fix",
        {
            "report": report_id,
            "force": True,
            "status_override": "VERIFIED",
            "findings": [
                {"status": "VERIFIED", "evidence": {"poc_script": "x", "canary_token": "t"}}
            ],
        },
    )
    assert status == 409
    assert "eligible" in body["error"]
