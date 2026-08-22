"""Orchestrator tests: phase sequencing, degradation, and report assembly."""

from pathlib import Path
from typing import Any

import pytest

from mugiwara.agents.models import (
    AttackSurfaceMap,
    Endpoint,
    SuspectedFindingsReport,
    VerificationPlan,
)
from mugiwara.agents.orchestrator import (
    ScanOrchestrator,
    ScanRunResult,
    SessionPhase,
    run_scan,
)
from mugiwara.agents.poc_safety import POC_LOG_MARKER, TARGET_LOG_MARKER
from mugiwara.core.config import MugiwaraSettings, SandboxMode, ScanProfile
from mugiwara.core.exceptions import ProviderExecutionError, SandboxStartError, TargetPathError
from mugiwara.models.finding import FindingStatus, Severity
from mugiwara.models.report import ScanReport
from mugiwara.providers.mock import MockLLMProvider
from mugiwara.sandbox.base import ExecResult, WorkspaceMount
from mugiwara.sandbox.mock import MockSandbox

FIXTURE_APP = Path(__file__).resolve().parents[1] / "fixtures" / "sample_vulnerable_app"

FIXED_CANARY = "MUGIWARA_CANARY_fixed123"

SAFE_POC_SCRIPT = """\\
import json
import os
import urllib.request

url = os.environ["MUGIWARA_TARGET_URL"]
canary = os.environ["MUGIWARA_CANARY"]
request = urllib.request.Request(url + "/users?id=" + canary)
response = urllib.request.urlopen(request, timeout=5)
body = response.read().decode("utf-8", "replace")
status = int(response.status)
trace = {"method": "GET", "url": url + "/users?id=" + canary,
         "http_status": status, "response_body_snippet": body[:200]}
print("MUGIWARA_HTTP_TRACE: " + json.dumps(trace))
verdict = {"canary_found": canary in body, "http_status": status, "notes": "reflection"}
print("MUGIWARA_VERDICT: " + json.dumps(verdict))
"""


def _settings(**overrides: Any) -> MugiwaraSettings:
    """Build hermetic settings (verification off) with optional agent overrides."""
    settings = MugiwaraSettings()
    settings.sandbox.mode = SandboxMode.NONE
    for key, value in overrides.items():
        setattr(settings.agents, key, value)
    return settings


def _install_provider(monkeypatch: pytest.MonkeyPatch, provider: MockLLMProvider) -> None:
    """Force the orchestrator factory to return the given mock provider."""
    monkeypatch.setattr(
        "mugiwara.agents.orchestrator.get_provider",
        lambda _config: provider,
    )


def _install_sandbox(monkeypatch: pytest.MonkeyPatch, sandbox: MockSandbox) -> None:
    """Force the orchestrator factory to return the given mock sandbox."""
    monkeypatch.setattr(
        "mugiwara.agents.orchestrator.get_sandbox",
        lambda _config: sandbox,
    )


def _verified_harness_stdout(canary: str) -> str:
    """Compose harness output proving canary reflection."""
    trace = '{"method": "GET", "url": "http://127.0.0.1:5000/users", "http_status": 200}'
    return (
        f"{TARGET_LOG_MARKER}\n"
        " * Running on http://127.0.0.1:5000\n"
        f"{POC_LOG_MARKER}\n"
        f'{{"echo": "{canary}"}}\n'
        f"MUGIWARA_HTTP_TRACE: {trace}\n"
        'MUGIWARA_VERDICT: {"canary_found": true, "http_status": 200, "notes": "reflected"}\n'
        "MUGIWARA_EXIT:0 READY:0\n"
    )


async def test_full_pipeline_completes_both_phases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify a healthy run completes recon and discovery and emits findings."""
    provider = MockLLMProvider()
    provider.add_structured_response(AttackSurfaceMap(summary="Flask service."))
    provider.add_structured_response(SuspectedFindingsReport(findings=[]))
    _install_provider(monkeypatch, provider)

    result = await ScanOrchestrator(_settings()).run(str(FIXTURE_APP))

    assert isinstance(result, ScanRunResult)
    assert result.phases_completed == [SessionPhase.RECON, SessionPhase.DISCOVERY]
    assert result.report.findings, "heuristic findings must survive empty LLM report"
    assert all(f.status is FindingStatus.SUSPECTED for f in result.report.findings)
    assert any(f.severity is Severity.HIGH for f in result.report.findings)
    assert any(f.location is not None for f in result.report.findings)
    assert result.diagnostics.degraded is False
    assert result.report.completed_at is not None
    assert result.diagnostics.files_collected > 0
    assert result.diagnostics.llm_calls >= 2
    assert result.diagnostics.tokens_used > 0


async def test_report_summary_matches_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify calculate_summary aggregates the emitted findings."""
    provider = MockLLMProvider()
    _install_provider(monkeypatch, provider)

    result = await ScanOrchestrator(_settings()).run(str(FIXTURE_APP))

    summary = result.report.summary
    assert summary.total_findings == len(result.report.findings)
    assert summary.suspected_count == summary.total_findings
    high = len([f for f in result.report.findings if f.severity is Severity.HIGH])
    assert summary.high_count == high


async def test_report_serializes_to_json_roundtrip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify the assembled report round-trips through JSON cleanly."""
    provider = MockLLMProvider()
    _install_provider(monkeypatch, provider)

    result = await ScanOrchestrator(_settings()).run(str(FIXTURE_APP))

    raw = result.report.model_dump_json()
    parsed = ScanReport.model_validate_json(raw)

    assert parsed.target_path == result.report.target_path
    assert len(parsed.findings) == len(result.report.findings)


async def test_missing_target_raises_before_agents(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify invalid targets abort during validation without touching agents."""
    _install_provider(monkeypatch, MockLLMProvider())
    orchestrator = ScanOrchestrator(_settings())

    with pytest.raises(TargetPathError):
        await orchestrator.run("Z:/definitely/not/a/real/path")

    assert orchestrator.phase is SessionPhase.VALIDATING


async def test_provider_failure_degrades_but_completes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify both phases still complete when every LLM call fails."""
    provider = MockLLMProvider()
    provider.set_error(ProviderExecutionError("provider offline"))
    _install_provider(monkeypatch, provider)

    result = await ScanOrchestrator(_settings()).run(str(FIXTURE_APP))

    assert result.phases_completed == [SessionPhase.RECON, SessionPhase.DISCOVERY]
    assert result.diagnostics.degraded is True
    assert result.diagnostics.errors, "degradation reasons must be recorded"
    assert result.report.findings, "heuristic findings must remain available"


async def test_budget_exhaustion_degrades_gracefully(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify an exhausted token budget yields heuristic-only output."""
    provider = MockLLMProvider()
    _install_provider(monkeypatch, provider)

    result = await ScanOrchestrator(_settings(max_total_tokens=1)).run(str(FIXTURE_APP))

    assert result.phases_completed == [SessionPhase.RECON, SessionPhase.DISCOVERY]
    assert result.diagnostics.degraded is True
    assert result.report.findings
    assert result.diagnostics.tokens_used <= 1


async def test_recon_surface_flows_into_discovery_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify discovery prompts include the reconnaissance summary block."""
    provider = MockLLMProvider()
    provider.add_structured_response(AttackSurfaceMap(summary="Tiny Flask app."))
    _install_provider(monkeypatch, provider)
    orchestrator = ScanOrchestrator(_settings())

    result = await orchestrator.run(str(FIXTURE_APP))

    discovery_calls = [
        call for call in provider.call_history if "candidate locations" in call.prompt.lower()
    ]
    assert discovery_calls, "discovery must issue at least one LLM call"
    assert "Detected technology context from reconnaissance:" in discovery_calls[-1].prompt
    assert result.diagnostics.degraded is False


def test_sync_wrapper_runs_full_pipeline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify the synchronous run_scan helper completes end to end."""
    provider = MockLLMProvider()
    _install_provider(monkeypatch, provider)

    result = run_scan(_settings(), str(FIXTURE_APP))

    assert result.phases_completed == [SessionPhase.RECON, SessionPhase.DISCOVERY]
    assert result.report.findings


class _RecordingSandbox(MockSandbox):
    """Mock sandbox that remembers every mount passed to start()."""

    def __init__(self) -> None:
        super().__init__()
        self.start_mounts: list[WorkspaceMount | None] = []

    async def start(self, workspace_mount: WorkspaceMount | None = None) -> None:
        """Record the mount then delegate to the mock lifecycle."""
        self.start_mounts.append(workspace_mount)
        await super().start(workspace_mount)


async def test_verification_flips_suspected_to_verified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify the mock full pipeline flips a reachable SQLi finding to VERIFIED."""
    provider = MockLLMProvider()
    provider.add_structured_response(
        AttackSurfaceMap(
            summary="Flask service.",
            endpoints=[Endpoint(path="/users", method="GET", source_file="routes.py")],
        )
    )
    provider.add_structured_response(SuspectedFindingsReport(findings=[]))
    provider.add_structured_response(VerificationPlan(finding_ref=0, poc_script=SAFE_POC_SCRIPT))
    _install_provider(monkeypatch, provider)

    sandbox = _RecordingSandbox()
    sandbox.add_result(
        ExecResult(
            command=["sh", "-c", "harness"],
            exit_code=0,
            stdout=_verified_harness_stdout(FIXED_CANARY),
            duration_seconds=0.5,
        )
    )
    _install_sandbox(monkeypatch, sandbox)
    monkeypatch.setattr(
        "mugiwara.agents.verification.gen_canary_token",
        lambda: FIXED_CANARY,
    )

    settings = MugiwaraSettings()
    settings.sandbox.mode = SandboxMode.MOCK

    result = await ScanOrchestrator(settings).run(str(FIXTURE_APP))

    assert result.phases_completed == [
        SessionPhase.RECON,
        SessionPhase.DISCOVERY,
        SessionPhase.VERIFICATION,
    ]
    statuses = {f.status for f in result.report.findings}
    assert FindingStatus.VERIFIED in statuses
    verified = [f for f in result.report.findings if f.status is FindingStatus.VERIFIED]
    assert len(verified) == 1
    assert verified[0].category.value == "sql_injection"
    evidence = verified[0].evidence
    assert evidence is not None
    assert evidence.canary_token == FIXED_CANARY
    assert evidence.canary_found is True
    assert evidence.poc_script == SAFE_POC_SCRIPT
    assert evidence.http_trace is not None
    assert evidence.http_trace.response_status_code == 200
    assert evidence.verified_at is not None
    diagnostics = result.diagnostics
    assert diagnostics.verification_candidates == 1
    assert diagnostics.verification_attempted == 1
    assert diagnostics.verification_verified == 1
    assert diagnostics.sandbox_backend == "mock"
    assert diagnostics.staging_files > 0
    assert sandbox.stop_count == 1
    assert sandbox.start_mounts and sandbox.start_mounts[0] is not None
    assert sandbox.start_mounts[0].read_only is False


async def test_verification_docker_unavailable_degrades(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify a failing sandbox backend degrades without touching finding status."""

    def _raise(_config: object) -> object:
        raise SandboxStartError("docker daemon unreachable")

    provider = MockLLMProvider()
    _install_provider(monkeypatch, provider)
    monkeypatch.setattr("mugiwara.agents.orchestrator.get_sandbox", _raise)

    settings = MugiwaraSettings()
    result = await ScanOrchestrator(settings).run(str(FIXTURE_APP))

    assert SessionPhase.VERIFICATION not in result.phases_completed
    assert result.diagnostics.degraded is True
    assert any("verification phase failed" in error for error in result.diagnostics.errors)
    assert all(f.status is FindingStatus.SUSPECTED for f in result.report.findings)


async def test_fast_profile_skips_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify the fast profile never enters the verification phase."""
    provider = MockLLMProvider()
    _install_provider(monkeypatch, provider)

    settings = MugiwaraSettings()
    settings.sandbox.mode = SandboxMode.MOCK
    settings.scan.profile = ScanProfile.FAST
    result = await ScanOrchestrator(settings).run(str(FIXTURE_APP))

    assert result.phases_completed == [SessionPhase.RECON, SessionPhase.DISCOVERY]
    assert result.diagnostics.sandbox_backend is None
    assert all(f.status is FindingStatus.SUSPECTED for f in result.report.findings)
