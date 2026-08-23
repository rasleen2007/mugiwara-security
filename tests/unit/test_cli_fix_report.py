"""Tests for 'mugiwara fix --report': consuming persisted reports without rescanning.

All LLM/sandbox backends are mocked; a tripwire replaces ScanOrchestrator so
any accidental scan invocation fails the test immediately.
"""

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from mugiwara.agents.poc_safety import POC_LOG_MARKER, TARGET_LOG_MARKER
from mugiwara.cli.main import app
from mugiwara.core.config import MugiwaraSettings, SandboxMode
from mugiwara.core.exceptions import MugiwaraError, ReportTargetMismatchError
from mugiwara.models.evidence import Evidence
from mugiwara.models.finding import (
    Finding,
    FindingStatus,
    Severity,
    SourceLocation,
    VulnerabilityCategory,
)
from mugiwara.models.report import ScanReport
from mugiwara.providers.mock import MockLLMProvider
from mugiwara.remediation.service import RemediationService
from mugiwara.reports.store import ReportStore, ScanConfigurationSnapshot, TargetMetadata
from mugiwara.sandbox.base import ExecResult
from mugiwara.sandbox.mock import MockSandbox

runner = CliRunner()

CANARY = "MUGIWARA_CANARY_rep7"

TARGET_SOURCE = '''\
"""Tiny coherent Flask target used to exercise remediation flows."""

import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/users")
def list_users():
    """List users matching an unfiltered name parameter."""
    username = request.args.get("username", "")
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    rows = str(cursor.fetchall())
    connection.close()
    return rows


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
'''

POC_SCRIPT = """\
import json
import os
import urllib.request

url = os.environ["MUGIWARA_TARGET_URL"]
canary = os.environ["MUGIWARA_CANARY"]
body = urllib.request.urlopen(url + "/users?username=" + canary, timeout=5).read().decode()
verdict = {"canary_found": canary in body, "http_status": 200, "notes": "reflection"}
print("MUGIWARA_VERDICT: " + json.dumps(verdict))
"""


class _ScannerTripwire:
    """Stand-in for ScanOrchestrator that fails if anyone tries to scan."""

    def __init__(self, _settings: MugiwaraSettings) -> None:
        pass

    async def run(self, *_args: Any) -> Any:
        raise AssertionError("scanner must not be invoked when consuming a report")


def _verified_finding(**overrides: Any) -> Finding:
    values: dict[str, Any] = {
        "title": "Dynamic SQL construction",
        "description": "User input is interpolated into a SQL statement.",
        "category": VulnerabilityCategory.SQL_INJECTION,
        "severity": Severity.HIGH,
        "cwe_id": "CWE-89",
        "location": SourceLocation(file_path="app.py", start_line=15),
        "status": FindingStatus.VERIFIED,
        "evidence": Evidence(
            poc_script=POC_SCRIPT,
            canary_token=CANARY,
            canary_found=True,
            reproduction_steps=["step one"],
        ),
    }
    values.update(overrides)
    return Finding(**values)


def _make_project(tmp_path: Path, name: str = "proj") -> Path:
    root = tmp_path / name
    root.mkdir()
    (root / "app.py").write_text(TARGET_SOURCE, encoding="utf-8")
    return root


def _save_report(
    root: Path,
    findings: list[Finding],
    tmp_path: Path,
) -> str:
    report = ScanReport(target_path=str(root), findings=findings)
    report.calculate_summary()
    store = ReportStore(root=root / ".mugiwara" / "reports")
    envelope = store.save(
        report,
        target=TargetMetadata(path=str(root), origin="directory"),
        configuration=ScanConfigurationSnapshot(
            scan_profile="standard",
            llm_provider="mock",
            llm_model="mock-analyst",
            sandbox_mode="mock",
            verification_enabled=True,
            include_evidence=True,
        ),
    )
    assert envelope.target.path == str(root)
    del tmp_path
    return envelope.report_id


def _patch_backends(
    monkeypatch: pytest.MonkeyPatch,
) -> MockSandbox:
    sandbox = MockSandbox()
    monkeypatch.setattr("mugiwara.remediation.service.get_sandbox", lambda _config, **_: sandbox)
    monkeypatch.setattr(
        "mugiwara.remediation.service.get_provider", lambda _config: MockLLMProvider()
    )
    monkeypatch.setattr("mugiwara.remediation.service.ScanOrchestrator", _ScannerTripwire)
    return sandbox


def _clean_sea_trial(sandbox: MockSandbox) -> None:
    stdout = (
        "\n".join(
            [
                TARGET_LOG_MARKER,
                " * Running on http://127.0.0.1:5000",
                POC_LOG_MARKER,
                'MUGIWARA_VERDICT: {"canary_found": false, "http_status": 200, "notes": "t"}',
                "MUGIWARA_EXIT:0 READY:0",
            ]
        )
        + "\n"
    )
    sandbox.add_result(
        ExecResult(
            command=["sh", "-c", "harness"],
            exit_code=0,
            stdout=stdout,
            duration_seconds=0.25,
            timed_out=False,
        )
    )


def _settings() -> MugiwaraSettings:
    settings = MugiwaraSettings()
    settings.sandbox.mode = SandboxMode.MOCK
    return settings


# -- service level ------------------------------------------------------------------


async def test_run_stored_report_consumes_findings_without_scanner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stored verified findings are remediated; the scanner is never touched."""
    root = _make_project(tmp_path)
    finding = _verified_finding()
    report_id = _save_report(root, [finding], tmp_path)

    sandbox = _patch_backends(monkeypatch)
    _clean_sea_trial(sandbox)

    store = ReportStore(root=root / ".mugiwara" / "reports")
    envelope = store.load(report_id)

    result = await RemediationService(_settings()).run_stored_report(
        envelope, project_root=str(root)
    )

    assert len(result.report.records) == 1
    record = result.report.records[0]
    assert record.status.value == "VERIFIED_FIXED"
    assert record.finding_id == str(finding.id)
    assert record.location.startswith("app.py:")
    assert result.scan.phases_completed == []
    assert (root / "app.py").read_text(encoding="utf-8") == TARGET_SOURCE


async def test_run_stored_report_rejects_mismatched_project_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Findings cannot be steered into a different tree than was scanned."""
    root = _make_project(tmp_path, name="scanned")
    other = _make_project(tmp_path, name="other")
    report_id = _save_report(root, [_verified_finding()], tmp_path)

    _patch_backends(monkeypatch)

    envelope = ReportStore(root=root / ".mugiwara" / "reports").load(report_id)
    service = RemediationService(_settings())

    with pytest.raises(ReportTargetMismatchError, match="not the requested project root"):
        await service.run_stored_report(envelope, project_root=str(other))

    assert (other / "app.py").read_text(encoding="utf-8") == TARGET_SOURCE


async def test_run_stored_report_requires_existing_project_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A nonexistent project root fails closed before anything is staged."""
    root = _make_project(tmp_path)
    report_id = _save_report(root, [_verified_finding()], tmp_path)
    _patch_backends(monkeypatch)

    envelope = ReportStore(root=root / ".mugiwara" / "reports").load(report_id)

    with pytest.raises(MugiwaraError, match="does not exist"):
        await RemediationService(_settings()).run_stored_report(
            envelope, project_root=str(root.parent / "ghost")
        )


async def test_run_stored_report_without_verified_findings_notes_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Suspected-only stored reports yield an honest empty run, still unscanned."""
    root = _make_project(tmp_path)
    suspected = _verified_finding(status=FindingStatus.SUSPECTED, evidence=None)
    report_id = _save_report(root, [suspected], tmp_path)
    _patch_backends(monkeypatch)

    envelope = ReportStore(root=root / ".mugiwara" / "reports").load(report_id)
    result = await RemediationService(_settings()).run_stored_report(
        envelope, project_root=str(root)
    )

    assert result.report.records == []
    assert any("No dynamically verified findings" in note for note in result.report.notes)


async def test_run_stored_report_respects_max_findings_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The per-run cap applies to stored findings exactly as to fresh ones."""
    root = _make_project(tmp_path)
    findings = [_verified_finding(title=f"Finding {index}") for index in range(3)]
    report_id = _save_report(root, findings, tmp_path)

    sandbox = _patch_backends(monkeypatch)
    _clean_sea_trial(sandbox)
    _clean_sea_trial(sandbox)

    envelope = ReportStore(root=root / ".mugiwara" / "reports").load(report_id)
    result = await RemediationService(_settings(), max_findings=2).run_stored_report(
        envelope, project_root=str(root)
    )

    assert len(result.report.records) == 2
    assert any("capped at 2 of 3" in note for note in result.report.notes)


# -- CLI level ------------------------------------------------------------------------


def _cli_patches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> MockSandbox:
    sandbox = _patch_backends(monkeypatch)
    monkeypatch.chdir(tmp_path)
    return sandbox


def test_cli_fix_report_happy_path_skips_scanner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End to end: fix --report remediates the stored finding and exits 0."""
    root = _make_project(tmp_path)
    report_id = _save_report(root, [_verified_finding()], tmp_path)
    sandbox = _cli_patches(tmp_path, monkeypatch)
    _clean_sea_trial(sandbox)

    result = runner.invoke(app, ["fix", str(root), "--report", report_id])

    assert result.exit_code == 0, result.stdout
    assert "VERIFIED_FIXED" in result.stdout
    assert "the scanner is not run" in result.stdout
    assert (root / "app.py").read_text(encoding="utf-8") == TARGET_SOURCE


def test_cli_fix_report_writes_bundle_from_stored_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The fix bundle reflects stored findings without a fresh pipeline run."""
    root = _make_project(tmp_path)
    report_id = _save_report(root, [_verified_finding()], tmp_path)
    sandbox = _cli_patches(tmp_path, monkeypatch)
    _clean_sea_trial(sandbox)
    bundle_path = tmp_path / "bundle.json"

    result = runner.invoke(
        app,
        ["fix", str(root), "--report", report_id, "--output", str(bundle_path)],
    )

    assert result.exit_code == 0, result.stdout
    content = bundle_path.read_text(encoding="utf-8")
    assert '"schema": "mugiwara.fix-bundle"' in content
    assert '"pipeline_phases": []' in content
    assert "Dynamic SQL construction" in content


def test_cli_fix_report_unknown_reference_exits_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _cli_patches(tmp_path, monkeypatch)
    root = _make_project(tmp_path)
    _save_report(root, [_verified_finding()], tmp_path)

    result = runner.invoke(app, ["fix", str(root), "--report", "20990101T000000-deadbeef00"])

    assert result.exit_code == 1
    assert "Could not load stored report" in result.stderr


def test_cli_fix_report_escaping_reference_is_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _cli_patches(tmp_path, monkeypatch)
    root = _make_project(tmp_path)
    _save_report(root, [_verified_finding()], tmp_path)

    result = runner.invoke(app, ["fix", str(root), "--report", "../../escape.json"])

    assert result.exit_code == 1
    assert "escapes the report store" in result.stderr


def test_cli_fix_report_project_root_mismatch_exits_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An explicit but wrong project root is refused before patching."""
    root = _make_project(tmp_path, name="scanned")
    other = _make_project(tmp_path, name="other")
    report_id = _save_report(root, [_verified_finding()], tmp_path)
    _cli_patches(tmp_path, monkeypatch)

    result = runner.invoke(
        app,
        ["fix", str(root), "--report", report_id, "--project-root", str(other)],
    )

    assert result.exit_code == 1
    assert "not the requested project root" in result.stderr
    assert (other / "app.py").read_text(encoding="utf-8") == TARGET_SOURCE


def test_cli_fix_without_report_still_scans(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression guard: the classic fix path keeps invoking the scanner."""
    root = _make_project(tmp_path)
    _cli_patches(tmp_path, monkeypatch)

    class ExplodingOrchestrator:
        def __init__(self, _settings: MugiwaraSettings) -> None:
            pass

        async def run(self, *_args: Any) -> Any:
            raise MugiwaraError("orchestrator-was-invoked")

    monkeypatch.setattr("mugiwara.remediation.service.ScanOrchestrator", ExplodingOrchestrator)

    result = runner.invoke(app, ["fix", str(root)])

    assert result.exit_code == 1
    assert "orchestrator-was-invoked" in result.stderr
