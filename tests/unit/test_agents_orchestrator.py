"""Orchestrator tests: phase sequencing, degradation, and report assembly."""

from pathlib import Path
from typing import Any

import pytest

from mugiwara.agents.models import AttackSurfaceMap, SuspectedFindingsReport
from mugiwara.agents.orchestrator import (
    ScanOrchestrator,
    ScanRunResult,
    SessionPhase,
    run_scan,
)
from mugiwara.core.config import MugiwaraSettings
from mugiwara.core.exceptions import ProviderExecutionError, TargetPathError
from mugiwara.models.finding import FindingStatus, Severity
from mugiwara.models.report import ScanReport
from mugiwara.providers.mock import MockLLMProvider

FIXTURE_APP = Path(__file__).resolve().parents[1] / "fixtures" / "sample_vulnerable_app"


def _settings(**overrides: Any) -> MugiwaraSettings:
    """Build settings with optional agent-config overrides."""
    settings = MugiwaraSettings()
    for key, value in overrides.items():
        setattr(settings.agents, key, value)
    return settings


def _install_provider(monkeypatch: pytest.MonkeyPatch, provider: MockLLMProvider) -> None:
    """Force the orchestrator factory to return the given mock provider."""
    monkeypatch.setattr(
        "mugiwara.agents.orchestrator.get_provider",
        lambda _config: provider,
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
