"""Unit tests for the dynamic exploit verification agent."""

from pathlib import Path

import pytest

from mugiwara.agents.base import AgentContext
from mugiwara.agents.models import AttackSurfaceMap, Endpoint, VerificationPlan
from mugiwara.agents.staging import StagingWorkspace
from mugiwara.agents.verification import VerificationAgent
from mugiwara.core.config import MugiwaraSettings
from mugiwara.core.exceptions import VerificationUnavailableError
from mugiwara.models.finding import (
    Finding,
    FindingStatus,
    Severity,
    SourceLocation,
    VulnerabilityCategory,
)
from mugiwara.providers.mock import MockLLMProvider
from mugiwara.sandbox.base import ExecResult
from mugiwara.sandbox.mock import MockSandbox
from tests.unit.test_agents_orchestrator import FIXED_CANARY, SAFE_POC_SCRIPT

APP_SOURCE = "print('target app')\n"


def _finding(
    *,
    file_path: str = "routes.py",
    category: VulnerabilityCategory = VulnerabilityCategory.SQL_INJECTION,
) -> Finding:
    """Build one suspected finding with a concrete location."""
    return Finding(
        title="SQL injection in users handler",
        description="Dynamic SQL built from request parameters.",
        category=category,
        severity=Severity.HIGH,
        cwe_id="CWE-89",
        location=SourceLocation(file_path=file_path, start_line=17, snippet="cur.execute(...)"),
    )


def _surface(source_file: str = "routes.py") -> AttackSurfaceMap:
    """Build an attack surface declaring one endpoint for the given file."""
    return AttackSurfaceMap(
        summary="Flask service.",
        endpoints=[Endpoint(path="/users", method="GET", source_file=source_file)],
    )


def _ctx(provider: MockLLMProvider, findings: list[Finding]) -> AgentContext:
    """Assemble a session context over a tiny collected source set."""
    from mugiwara.agents.sources import CollectedSources, SourceFile

    sources = CollectedSources(
        files=[
            SourceFile(
                relative_path="app.py",
                absolute_path=Path("/targets/demo/app.py"),
                size_bytes=len(APP_SOURCE.encode("utf-8")),
                line_count=1,
                content=APP_SOURCE,
            )
        ],
        secret_markers=[],
    )
    ctx = AgentContext(
        provider=provider,
        settings=MugiwaraSettings(),
        sources=sources,
        target_root="/targets/demo",
    )
    ctx.findings = findings
    ctx.attack_surface = _surface()
    return ctx


def _harness_output(
    *,
    canary_echo: bool,
    verdict_json: str,
    exit_code: int = 0,
    ready: int = 0,
    target_log: str = " * Running on http://127.0.0.1:5000",
) -> str:
    """Compose harness stdout with configurable verdict, canary echo, and target log."""
    echo_line = f'{{"reflected": "{FIXED_CANARY}"}}\n' if canary_echo else ""
    trace = '{"method": "GET", "url": "http://127.0.0.1:5000/users", "http_status": 200}'
    sections = [
        "===MUGIWARA_TARGET_LOG===",
        target_log,
        "===MUGIWARA_POC_LOG===",
        echo_line,
        f"MUGIWARA_HTTP_TRACE: {trace}",
        f"MUGIWARA_VERDICT: {verdict_json}",
        f"MUGIWARA_EXIT:{exit_code} READY:{ready}",
    ]
    return "\n".join(sections)


async def test_verified_outcome_attaches_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify a reflected canary flips the finding to VERIFIED with full evidence."""
    provider = MockLLMProvider()
    provider.add_structured_response(VerificationPlan(finding_ref=0, poc_script=SAFE_POC_SCRIPT))
    sandbox = MockSandbox()
    await sandbox.start()
    sandbox.add_result(
        ExecResult(
            command=["sh", "-c", "harness"],
            exit_code=0,
            stdout=_harness_output(canary_echo=True, verdict_json='{"canary_found": true}'),
            duration_seconds=0.75,
        )
    )
    monkeypatch.setattr("mugiwara.agents.verification.gen_canary_token", lambda: FIXED_CANARY)

    finding = _finding()
    ctx = _ctx(provider, [finding])

    with StagingWorkspace(ctx.sources) as staging:
        ctx.sandbox = sandbox
        ctx.staging = staging
        processed = await VerificationAgent().run(ctx)

    assert len(processed) == 1
    assert processed[0].status is FindingStatus.VERIFIED
    evidence = processed[0].evidence
    assert evidence is not None
    assert evidence.poc_script == SAFE_POC_SCRIPT
    assert evidence.canary_token == FIXED_CANARY
    assert evidence.canary_found is True
    assert evidence.http_trace is not None
    assert evidence.http_trace.response_status_code == 200
    assert evidence.verified_at is not None
    assert evidence.verified_at.tzinfo is not None
    assert evidence.sandbox_runtime_seconds == pytest.approx(0.75)
    assert evidence.stdout_log is not None and "Running on" in evidence.stdout_log
    diagnostics = ctx.diagnostics
    assert diagnostics.verification_candidates == 1
    assert diagnostics.verification_attempted == 1
    assert diagnostics.verification_verified == 1
    assert diagnostics.verification_false_positives == 0
    assert diagnostics.verification_unverified == 0
    assert diagnostics.sandbox_backend == "mock"
    assert diagnostics.staging_files > 0
    assert sandbox.call_history[0][0] == "sh"
    assert sandbox.stop_count == 0


async def test_false_positive_outcome_eliminated(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify a clean probe eliminates the finding as FALSE_POSITIVE."""
    provider = MockLLMProvider()
    provider.add_structured_response(VerificationPlan(finding_ref=0, poc_script=SAFE_POC_SCRIPT))
    sandbox = MockSandbox()
    await sandbox.start()
    sandbox.add_result(
        ExecResult(
            command=["sh", "-c", "harness"],
            exit_code=0,
            stdout=_harness_output(canary_echo=False, verdict_json='{"canary_found": false}'),
            duration_seconds=0.2,
        )
    )
    monkeypatch.setattr("mugiwara.agents.verification.gen_canary_token", lambda: FIXED_CANARY)

    finding = _finding()
    ctx = _ctx(provider, [finding])

    with StagingWorkspace(ctx.sources) as staging:
        ctx.sandbox = sandbox
        ctx.staging = staging
        processed = await VerificationAgent().run(ctx)

    assert processed[0].status is FindingStatus.FALSE_POSITIVE
    evidence = processed[0].evidence
    assert evidence is not None
    assert evidence.canary_found is False
    assert ctx.diagnostics.verification_false_positives == 1
    assert ctx.diagnostics.verification_verified == 0


async def test_timeout_keeps_finding_suspected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify a timed-out probe records UNVERIFIED without status transition."""
    provider = MockLLMProvider()
    provider.add_structured_response(VerificationPlan(finding_ref=0, poc_script=SAFE_POC_SCRIPT))
    sandbox = MockSandbox()
    await sandbox.start()
    sandbox.add_result(ExecResult(command=["sh", "-c"], timed_out=True, duration_seconds=30.0))
    monkeypatch.setattr("mugiwara.agents.verification.gen_canary_token", lambda: FIXED_CANARY)

    finding = _finding()
    ctx = _ctx(provider, [finding])

    with StagingWorkspace(ctx.sources) as staging:
        ctx.sandbox = sandbox
        ctx.staging = staging
        processed = await VerificationAgent().run(ctx)

    assert processed[0].status is FindingStatus.SUSPECTED
    assert processed[0].evidence is None
    assert ctx.diagnostics.verification_unverified == 1
    assert ctx.diagnostics.verification_attempted == 1
    assert any("timed out" in error for error in ctx.diagnostics.errors)


@pytest.mark.parametrize(
    ("stdout", "reason_fragment"),
    [
        (_harness_output(canary_echo=False, verdict_json="{oops", exit_code=0), "verdict"),
        (
            _harness_output(canary_echo=False, verdict_json='{"canary_found": false}', exit_code=1),
            "nonzero",
        ),
        (
            _harness_output(canary_echo=False, verdict_json='{"canary_found": false}', ready=1),
            "readiness",
        ),
    ],
)
async def test_inconclusive_runs_stay_suspected(
    monkeypatch: pytest.MonkeyPatch,
    stdout: str,
    reason_fragment: str,
) -> None:
    """Verify malformed, crashed, and not-ready probes never change status."""
    provider = MockLLMProvider()
    provider.add_structured_response(VerificationPlan(finding_ref=0, poc_script=SAFE_POC_SCRIPT))
    sandbox = MockSandbox()
    await sandbox.start()
    sandbox.add_result(
        ExecResult(command=["sh", "-c"], exit_code=0, stdout=stdout, duration_seconds=0.1)
    )
    monkeypatch.setattr("mugiwara.agents.verification.gen_canary_token", lambda: FIXED_CANARY)

    finding = _finding()
    ctx = _ctx(provider, [finding])

    with StagingWorkspace(ctx.sources) as staging:
        ctx.sandbox = sandbox
        ctx.staging = staging
        processed = await VerificationAgent().run(ctx)

    assert processed[0].status is FindingStatus.SUSPECTED
    assert processed[0].evidence is None
    assert ctx.diagnostics.verification_unverified == 1
    assert any(reason_fragment in error for error in ctx.diagnostics.errors)


async def test_readiness_failure_surfaces_dependency_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify a startup import crash is reported as the readiness root cause."""
    provider = MockLLMProvider()
    provider.add_structured_response(VerificationPlan(finding_ref=0, poc_script=SAFE_POC_SCRIPT))
    sandbox = MockSandbox()
    await sandbox.start()
    crash_log = (
        "Traceback (most recent call last):\n"
        '  File "/workspace/app.py", line 8, in <module>\n'
        "    import yaml\n"
        "ModuleNotFoundError: No module named 'yaml'"
    )
    sandbox.add_result(
        ExecResult(
            command=["sh", "-c"],
            exit_code=0,
            stdout=_harness_output(
                canary_echo=False,
                verdict_json='{"canary_found": false}',
                ready=1,
                target_log=crash_log,
            ),
            duration_seconds=10.2,
        )
    )
    monkeypatch.setattr("mugiwara.agents.verification.gen_canary_token", lambda: FIXED_CANARY)

    finding = _finding()
    ctx = _ctx(provider, [finding])

    with StagingWorkspace(ctx.sources) as staging:
        ctx.sandbox = sandbox
        ctx.staging = staging
        processed = await VerificationAgent().run(ctx)

    assert processed[0].status is FindingStatus.SUSPECTED
    assert processed[0].evidence is None
    errors = "\n".join(ctx.diagnostics.errors)
    assert "target failed its readiness wait" in errors
    assert "ModuleNotFoundError: No module named 'yaml'" in errors
    assert "sandbox.image" in errors


async def test_readiness_failure_without_output_is_generic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify a silent target keeps the generic readiness message."""
    provider = MockLLMProvider()
    provider.add_structured_response(VerificationPlan(finding_ref=0, poc_script=SAFE_POC_SCRIPT))
    sandbox = MockSandbox()
    await sandbox.start()
    sandbox.add_result(
        ExecResult(
            command=["sh", "-c"],
            exit_code=0,
            stdout=_harness_output(
                canary_echo=False,
                verdict_json='{"canary_found": false}',
                ready=1,
                target_log="",
            ),
            duration_seconds=10.2,
        )
    )
    monkeypatch.setattr("mugiwara.agents.verification.gen_canary_token", lambda: FIXED_CANARY)

    finding = _finding()
    ctx = _ctx(provider, [finding])

    with StagingWorkspace(ctx.sources) as staging:
        ctx.sandbox = sandbox
        ctx.staging = staging
        processed = await VerificationAgent().run(ctx)

    assert processed[0].status is FindingStatus.SUSPECTED
    errors = "\n".join(ctx.diagnostics.errors)
    assert "produced no startup output" in errors
    assert "sandbox.image" not in errors


async def test_readiness_failure_reports_last_output_for_other_crashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify non-import startup failures surface their final output line."""
    provider = MockLLMProvider()
    provider.add_structured_response(VerificationPlan(finding_ref=0, poc_script=SAFE_POC_SCRIPT))
    sandbox = MockSandbox()
    await sandbox.start()
    sandbox.add_result(
        ExecResult(
            command=["sh", "-c"],
            exit_code=0,
            stdout=_harness_output(
                canary_echo=False,
                verdict_json='{"canary_found": false}',
                ready=1,
                target_log="OSError: [Errno 98] Address already in use",
            ),
            duration_seconds=10.2,
        )
    )
    monkeypatch.setattr("mugiwara.agents.verification.gen_canary_token", lambda: FIXED_CANARY)

    finding = _finding()
    ctx = _ctx(provider, [finding])

    with StagingWorkspace(ctx.sources) as staging:
        ctx.sandbox = sandbox
        ctx.staging = staging
        processed = await VerificationAgent().run(ctx)

    assert processed[0].status is FindingStatus.SUSPECTED
    errors = "\n".join(ctx.diagnostics.errors)
    assert "last target output: OSError: [Errno 98] Address already in use" in errors
    assert "sandbox.image" not in errors


async def test_contradictory_verdict_is_not_verified(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify a claimed canary without observed token stays UNVERIFIED."""
    provider = MockLLMProvider()
    provider.add_structured_response(VerificationPlan(finding_ref=0, poc_script=SAFE_POC_SCRIPT))
    sandbox = MockSandbox()
    await sandbox.start()
    sandbox.add_result(
        ExecResult(
            command=["sh", "-c"],
            exit_code=0,
            stdout=_harness_output(canary_echo=False, verdict_json='{"canary_found": true}'),
            duration_seconds=0.1,
        )
    )
    monkeypatch.setattr("mugiwara.agents.verification.gen_canary_token", lambda: FIXED_CANARY)

    finding = _finding()
    ctx = _ctx(provider, [finding])

    with StagingWorkspace(ctx.sources) as staging:
        ctx.sandbox = sandbox
        ctx.staging = staging
        processed = await VerificationAgent().run(ctx)

    assert processed[0].status is FindingStatus.SUSPECTED
    assert any("never echoed" in error for error in ctx.diagnostics.errors)


async def test_screened_poc_is_never_executed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify safety rejections abort before any sandbox execution."""
    hostile_script = (
        "import os\n"
        "import shutil\n"
        "url = os.environ['MUGIWARA_TARGET_URL']\n"
        "shutil.rmtree('/workspace')\n"
    )
    provider = MockLLMProvider()
    provider.add_structured_response(VerificationPlan(finding_ref=0, poc_script=hostile_script))
    sandbox = MockSandbox()
    await sandbox.start()

    finding = _finding()
    ctx = _ctx(provider, [finding])

    with StagingWorkspace(ctx.sources) as staging:
        ctx.sandbox = sandbox
        ctx.staging = staging
        processed = await VerificationAgent().run(ctx)

    assert processed[0].status is FindingStatus.SUSPECTED
    assert sandbox.call_history == []
    assert ctx.diagnostics.verification_attempted == 0
    assert ctx.diagnostics.dropped_references == 1
    assert any("rejected by safety screening" in error for error in ctx.diagnostics.errors)


async def test_mismatched_finding_reference_is_dropped(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify plans referencing unexpected candidate indexes are rejected."""
    provider = MockLLMProvider()
    provider.add_structured_response(VerificationPlan(finding_ref=7, poc_script=SAFE_POC_SCRIPT))
    sandbox = MockSandbox()
    await sandbox.start()

    finding = _finding()
    ctx = _ctx(provider, [finding])

    with StagingWorkspace(ctx.sources) as staging:
        ctx.sandbox = sandbox
        ctx.staging = staging
        processed = await VerificationAgent().run(ctx)

    assert processed[0].status is FindingStatus.SUSPECTED
    assert sandbox.call_history == []
    assert ctx.diagnostics.dropped_references == 1


async def test_missing_sandbox_raises() -> None:
    """Verify dynamic verification refuses to run without an attached sandbox."""
    provider = MockLLMProvider()
    ctx = _ctx(provider, [_finding()])

    with StagingWorkspace(ctx.sources) as staging:
        ctx.staging = staging
        with pytest.raises(VerificationUnavailableError):
            await VerificationAgent().run(ctx)


async def test_unreachable_findings_are_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify findings without matching recon endpoints remain SUSPECTED."""
    provider = MockLLMProvider()
    sandbox = MockSandbox()
    await sandbox.start()

    reachable = _finding()
    unreachable = _finding(file_path="models.py")
    unsupported = _finding(category=VulnerabilityCategory.HARDCODED_SECRET)
    ctx = _ctx(provider, [reachable, unreachable, unsupported])
    ctx.attack_surface = _surface("routes.py")

    with StagingWorkspace(ctx.sources) as staging:
        ctx.sandbox = sandbox
        ctx.staging = staging
        processed = await VerificationAgent().run(ctx)

    assert len(processed) == 1
    assert processed[0].status is FindingStatus.SUSPECTED
    assert unreachable.status is FindingStatus.SUSPECTED
    assert unsupported.status is FindingStatus.SUSPECTED
    assert ctx.diagnostics.verification_candidates == 1
    assert any("no recon-declared HTTP endpoint" in error for error in ctx.diagnostics.errors)


async def test_execution_budget_cap_respected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify max_poc_executions limits how many candidates are attempted."""
    provider = MockLLMProvider()
    provider.add_structured_response(VerificationPlan(finding_ref=0, poc_script=SAFE_POC_SCRIPT))
    sandbox = MockSandbox()
    await sandbox.start()
    sandbox.add_result(
        ExecResult(
            command=["sh", "-c"],
            exit_code=0,
            stdout=_harness_output(canary_echo=True, verdict_json='{"canary_found": true}'),
            duration_seconds=0.1,
        )
    )
    monkeypatch.setattr("mugiwara.agents.verification.gen_canary_token", lambda: FIXED_CANARY)

    first = _finding()
    second = _finding()
    ctx = _ctx(provider, [first, second])
    ctx.settings.verification.max_poc_executions = 1

    with StagingWorkspace(ctx.sources) as staging:
        ctx.sandbox = sandbox
        ctx.staging = staging
        processed = await VerificationAgent().run(ctx)

    assert len(processed) == 1
    assert first.status is FindingStatus.VERIFIED
    assert second.status is FindingStatus.SUSPECTED
    assert ctx.diagnostics.verification_candidates == 2
    assert ctx.diagnostics.verification_attempted == 1


def test_harness_sections_parse(tmp_path: Path) -> None:
    """Verify harness output parsing splits logs and reads the exit marker."""
    from mugiwara.agents.verification import _HarnessOutput

    output = _HarnessOutput(_harness_output(canary_echo=True, verdict_json="{}"))

    assert output.exit_code == 0
    assert output.ready_ok is True
    assert "Running on" in output.target_log
    assert FIXED_CANARY in output.poc_log
