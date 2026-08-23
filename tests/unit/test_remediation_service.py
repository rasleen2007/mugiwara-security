"""Unit tests for the remediation service: confinement, isolation, truth table."""

from pathlib import Path

import pytest

from mugiwara.agents.base import AgentContext
from mugiwara.agents.models import RemediationPlan
from mugiwara.agents.orchestrator import SessionPhase
from mugiwara.agents.poc_safety import POC_LOG_MARKER, TARGET_LOG_MARKER
from mugiwara.agents.sources import WorkspaceCollector
from mugiwara.core.config import MugiwaraSettings, SandboxMode
from mugiwara.core.exceptions import SandboxStartError
from mugiwara.models.evidence import Evidence
from mugiwara.models.finding import (
    Finding,
    FindingStatus,
    Severity,
    SourceLocation,
    VulnerabilityCategory,
)
from mugiwara.models.remediation import RemediationRecord, RemediationStatus
from mugiwara.providers.mock import MockLLMProvider
from mugiwara.remediation.patches import sha256_text
from mugiwara.remediation.service import RemediationService, build_remediation_bundle
from mugiwara.sandbox.base import ExecResult
from mugiwara.sandbox.mock import MockSandbox

CANARY = "MUGIWARA_CANARY_unit42"

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


def _stdout(
    *,
    verdict: bool = True,
    echo_canary: str | None = None,
    exit_line: int = 0,
    ready: int = 0,
    target_log: str = " * Running on http://127.0.0.1:5000",
    include_markers: bool = True,
    include_verdict: bool = True,
) -> str:
    """Compose a harness stdout blob for sea-trial scenarios."""
    parts: list[str] = []
    if include_markers:
        parts += [TARGET_LOG_MARKER, target_log, POC_LOG_MARKER]
    else:
        parts.append(target_log)
    if echo_canary is not None:
        parts.append('{"echo": "' + echo_canary + '"}')
    if include_verdict:
        parts.append(
            'MUGIWARA_VERDICT: {"canary_found": '
            + str(verdict).lower()
            + ', "http_status": 200, "notes": "trial"}'
        )
    parts.append(f"MUGIWARA_EXIT:{exit_line} READY:{ready}")
    return "\n".join(parts) + "\n"


def _result(stdout: str, *, exit_code: int = 0, timed_out: bool = False) -> ExecResult:
    """Wrap a stdout blob into an ExecResult."""
    return ExecResult(
        command=["sh", "-c", "harness"],
        exit_code=None if timed_out else exit_code,
        stdout=stdout,
        duration_seconds=0.25,
        timed_out=timed_out,
    )


_UNSET = object()


async def _run_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    postfix: ExecResult | None = None,
    provider: MockLLMProvider | None = None,
    start_error: Exception | None = None,
    evidence_overrides: dict[str, object] | None = None,
    location: SourceLocation | None | object = _UNSET,
) -> tuple[RemediationRecord, Path]:
    """Drive one _remediate_one call against a tmp target with mock backends."""
    root = tmp_path / "target"
    root.mkdir()
    (root / "app.py").write_text(TARGET_SOURCE, encoding="utf-8")

    settings = MugiwaraSettings()
    settings.sandbox.mode = SandboxMode.MOCK
    prov = provider if provider is not None else MockLLMProvider()

    sources = WorkspaceCollector(settings.agents).collect(root)
    ctx = AgentContext(provider=prov, settings=settings, sources=sources, target_root=str(root))

    evidence_fields: dict[str, object] = {
        "poc_script": POC_SCRIPT,
        "canary_token": CANARY,
        "canary_found": True,
        "reproduction_steps": ["step one"],
    }
    evidence_fields.update(evidence_overrides or {})

    finding = Finding(
        title="Dynamic SQL construction",
        description="User input is interpolated into a SQL statement.",
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        cwe_id="CWE-89",
        location=(
            SourceLocation(file_path="app.py", start_line=15) if location is _UNSET else location
        ),
        status=FindingStatus.VERIFIED,
        evidence=Evidence(**evidence_fields),  # type: ignore[arg-type]
    )

    sandbox = MockSandbox()
    if postfix is not None:
        sandbox.add_result(postfix)
    if start_error is not None:
        sandbox.set_error(start_error)
    monkeypatch.setattr("mugiwara.remediation.service.get_sandbox", lambda _config, **_: sandbox)
    monkeypatch.setattr("mugiwara.remediation.service.get_provider", lambda _config: prov)

    service = RemediationService(settings)
    record = await service._remediate_one(ctx, finding, 0, "app.py", 5000)
    return record, root


async def test_happy_path_reaches_verified_fixed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Auto-synthesized plan + clean rerun yields VERIFIED_FIXED end to end."""
    record, root = await _run_one(tmp_path, monkeypatch, postfix=_result(_stdout(verdict=False)))

    assert record.status is RemediationStatus.VERIFIED_FIXED
    assert record.reason is not None and "no longer reproduces" in record.reason
    assert record.file_path == "app.py"
    assert record.unified_diff is not None
    assert '-    cursor.execute(f"SELECT' in record.unified_diff
    assert '+        "SELECT * FROM users WHERE name = ?",' in record.unified_diff
    patched = record.patched_content or ""
    assert "(username,)" in patched
    assert "'{username}'" not in patched
    assert record.original_content == TARGET_SOURCE
    assert record.original_poc_sha256 == sha256_text(POC_SCRIPT)
    evidence = record.post_validation_evidence
    assert evidence is not None
    assert evidence.canary_found is False
    assert evidence.canary_token == CANARY
    assert evidence.poc_script == POC_SCRIPT
    assert record.sandbox_backend == "mock"
    assert record.sandbox_session_id is not None
    assert record.validated_at is not None

    assert (root / "app.py").read_text(encoding="utf-8") == TARGET_SOURCE


async def test_exploit_persists_is_not_fixed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rerun that still echoes the canary must be NOT_FIXED, never success."""
    record, _root = await _run_one(
        tmp_path, monkeypatch, postfix=_result(_stdout(verdict=True, echo_canary=CANARY))
    )

    assert record.status is RemediationStatus.NOT_FIXED
    assert record.reason is not None and "still reproduces" in record.reason
    evidence = record.post_validation_evidence
    assert evidence is not None and evidence.canary_found is True


async def test_readiness_crash_fails_honestly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A patched target that cannot boot yields FAILED with the startup error."""
    record, _root = await _run_one(
        tmp_path,
        monkeypatch,
        postfix=_result(
            _stdout(ready=1, target_log='ModuleNotFoundError: No module named "flask"')
        ),
    )

    assert record.status is RemediationStatus.FAILED
    assert record.reason is not None
    assert "crashed during startup" in record.reason
    assert "original target is untouched" in record.reason


async def test_timeout_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Timed-out sea trials are FAILED, not silently successful."""
    record, _root = await _run_one(tmp_path, monkeypatch, postfix=_result("", timed_out=True))

    assert record.status is RemediationStatus.FAILED
    assert record.reason is not None and "timed out" in record.reason


async def test_missing_exit_marker_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Harness output without markers cannot masquerade as a completed trial."""
    record, _root = await _run_one(
        tmp_path, monkeypatch, postfix=_result("unrelated container noise\n")
    )

    assert record.status is RemediationStatus.FAILED
    assert record.reason is not None and "no exit marker" in record.reason


async def test_missing_verdict_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A booting target with no parsable verdict fails honestly."""
    record, _root = await _run_one(
        tmp_path, monkeypatch, postfix=_result(_stdout(include_verdict=False))
    )

    assert record.status is RemediationStatus.FAILED
    assert record.reason is not None and "no parsable MUGIWARA_VERDICT" in record.reason


async def test_claim_without_observation_is_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verdicts claiming exploitation without an observed token fail honestly."""
    record, _root = await _run_one(
        tmp_path, monkeypatch, postfix=_result(_stdout(verdict=True, echo_canary=None))
    )

    assert record.status is RemediationStatus.FAILED
    assert record.reason is not None and "inconclusive" in record.reason


async def test_nonzero_clean_exit_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nonzero exits under a clean claim are failures, not fixes."""
    record, _root = await _run_one(
        tmp_path, monkeypatch, postfix=_result(_stdout(verdict=False), exit_code=1)
    )

    assert record.status is RemediationStatus.FAILED
    assert record.reason is not None and "nonzero" in record.reason


async def test_sandbox_start_failure_marks_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Backend outages produce FAILED records carrying backend metadata."""
    record, _root = await _run_one(
        tmp_path, monkeypatch, start_error=SandboxStartError("daemon unreachable")
    )

    assert record.status is RemediationStatus.FAILED
    assert record.reason is not None and "sandbox could not start" in record.reason
    assert record.sandbox_backend == "mock"
    assert record.unified_diff is not None


async def test_plan_targeting_uncollected_file_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Patches escaping the collected-source set are confined away."""
    provider = MockLLMProvider()
    provider.add_structured_response(
        RemediationPlan(
            finding_ref=0,
            file_path="../../etc/passwd",
            patched_content="x = 1\n",
            explanation="escape attempt",
        )
    )
    record, _root = await _run_one(tmp_path, monkeypatch, provider=provider)

    assert record.status is RemediationStatus.FAILED
    assert record.reason is not None and "not a collected" in record.reason
    assert record.patched_content is None


async def test_identical_patch_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No-op patches are refused instead of being celebrated as fixes."""
    provider = MockLLMProvider()
    provider.add_structured_response(
        RemediationPlan(
            finding_ref=0,
            file_path="app.py",
            patched_content=TARGET_SOURCE,
            explanation="unchanged",
        )
    )
    record, _root = await _run_one(tmp_path, monkeypatch, provider=provider)

    assert record.status is RemediationStatus.FAILED
    assert record.reason is not None and "identical" in record.reason


async def test_syntactically_broken_patch_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Patches that do not parse are stopped before any execution."""
    provider = MockLLMProvider()
    provider.add_structured_response(
        RemediationPlan(
            finding_ref=0,
            file_path="app.py",
            patched_content="def broken(:\n",
            explanation="oops",
        )
    )
    record, _root = await _run_one(tmp_path, monkeypatch, provider=provider)

    assert record.status is RemediationStatus.FAILED
    assert record.reason is not None and "syntax check" in record.reason


async def test_evidence_without_poc_fails_early(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without the original PoC there is nothing to re-run: honest refusal."""
    record, _root = await _run_one(tmp_path, monkeypatch, evidence_overrides={"poc_script": None})

    assert record.status is RemediationStatus.FAILED
    assert record.reason is not None and "PoC script" in record.reason


async def test_finding_without_location_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Findings without locations never receive guessed patch targets."""
    record, _root = await _run_one(tmp_path, monkeypatch, location=None)

    assert record.status is RemediationStatus.FAILED
    assert record.reason is not None and "no source location" in record.reason


async def test_full_run_end_to_end_auto_synth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ScanOrchestrator reuse: scan verifies via PoC, remediation proves the fix."""
    root = tmp_path / "appdir"
    root.mkdir()
    (root / "app.py").write_text(TARGET_SOURCE, encoding="utf-8")

    provider = MockLLMProvider()
    sandbox = MockSandbox()
    sandbox.add_result(_result(_stdout(verdict=True, echo_canary=CANARY)))
    sandbox.add_result(_result(_stdout(verdict=False)))

    monkeypatch.setattr("mugiwara.agents.orchestrator.get_provider", lambda _config: provider)
    monkeypatch.setattr("mugiwara.agents.orchestrator.get_sandbox", lambda _config, **_: sandbox)
    monkeypatch.setattr("mugiwara.remediation.service.get_provider", lambda _config: provider)
    monkeypatch.setattr("mugiwara.remediation.service.get_sandbox", lambda _config, **_: sandbox)
    monkeypatch.setattr("mugiwara.agents.verification.gen_canary_token", lambda: CANARY)

    settings = MugiwaraSettings()
    settings.sandbox.mode = SandboxMode.MOCK
    result = await RemediationService(settings).run(str(root))

    assert SessionPhase.VERIFICATION in result.scan.phases_completed
    verified = [f for f in result.scan.report.findings if f.status is FindingStatus.VERIFIED]
    assert len(verified) == 1
    assert len(result.report.records) == 1

    record = result.report.records[0]
    assert record.status is RemediationStatus.VERIFIED_FIXED
    assert record.finding_id == str(verified[0].id)
    assert record.location == "app.py:16"
    assert result.report.status_counts()["VERIFIED_FIXED"] == 1

    bundle = build_remediation_bundle(result, tool_version="test")
    assert bundle["summary"]["VERIFIED_FIXED"] == 1
    assert bundle["remediations"][0]["status"] == "VERIFIED_FIXED"

    assert (root / "app.py").read_text(encoding="utf-8") == TARGET_SOURCE


async def test_run_without_verified_findings_notes_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A clean scan yields an empty report with an honest note."""
    root = tmp_path / "clean"
    root.mkdir()
    (root / "main.py").write_text("value = 1\nprint(value)\n", encoding="utf-8")

    provider = MockLLMProvider()
    monkeypatch.setattr("mugiwara.agents.orchestrator.get_provider", lambda _config: provider)
    monkeypatch.setattr("mugiwara.remediation.service.get_provider", lambda _config: provider)

    settings = MugiwaraSettings()
    settings.sandbox.mode = SandboxMode.NONE
    result = await RemediationService(settings).run(str(root))

    assert result.report.records == []
    assert any("No dynamically verified findings" in note for note in result.report.notes)
    assert result.report.status_counts()["VERIFIED_FIXED"] == 0
