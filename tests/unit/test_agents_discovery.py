"""Unit tests for the discovery agent, including output confinement."""

from pathlib import Path

from mugiwara.agents.base import AgentContext
from mugiwara.agents.discovery import DiscoveryAgent
from mugiwara.agents.models import SuspectedFinding, SuspectedFindingsReport
from mugiwara.agents.sources import CollectedSources, SourceFile, WorkspaceCollector
from mugiwara.core.config import AgentConfig, MugiwaraSettings
from mugiwara.core.exceptions import ProviderExecutionError
from mugiwara.models.finding import FindingStatus, Severity, VulnerabilityCategory
from mugiwara.providers.mock import MockLLMProvider

FIXTURE_APP = Path(__file__).resolve().parents[1] / "fixtures" / "sample_vulnerable_app"

VULNERABLE_CONTENT = "\n".join(
    [
        "line one",
        "line two",
        "cursor.execute(f\"SELECT * FROM t WHERE x = '{v}'\")",
        "line four",
        "line five",
    ]
)


def _fixture_context(tmp_path: Path, provider: MockLLMProvider) -> AgentContext:
    """Build a context over the sample vulnerable app fixture."""
    sources = WorkspaceCollector(AgentConfig()).collect(FIXTURE_APP)
    return AgentContext(
        provider=provider,
        settings=MugiwaraSettings(),
        sources=sources,
        target_root=str(tmp_path),
    )


def _inline_context(provider: MockLLMProvider) -> AgentContext:
    """Build a context with a single synthetic vulnerable file."""
    source = SourceFile(
        relative_path="app.py",
        absolute_path=Path("app.py"),
        size_bytes=len(VULNERABLE_CONTENT),
        line_count=len(VULNERABLE_CONTENT.splitlines()),
        content=VULNERABLE_CONTENT,
    )
    return AgentContext(
        provider=provider,
        settings=MugiwaraSettings(),
        sources=CollectedSources(files=[source]),
        target_root=".",
    )


def _suspected(
    file_path: str = "app.py",
    start_line: int = 3,
    end_line: int | None = None,
) -> SuspectedFinding:
    """Build a valid suspected finding for the synthetic file."""
    return SuspectedFinding(
        title="SQL injection via f-string query",
        description="Untrusted input is interpolated directly into a SQL statement.",
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        cwe_id="CWE-89",
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
        rationale="String formatting inside execute().",
    )


async def test_heuristic_hits_always_produce_findings(tmp_path: Path) -> None:
    """Verify deterministic findings exist even when LLM adds nothing."""
    provider = MockLLMProvider()
    provider.add_structured_response(SuspectedFindingsReport(findings=[]))
    ctx = _fixture_context(tmp_path, provider)

    findings = await DiscoveryAgent().run(ctx)

    assert len(findings) >= 7
    assert all(finding.status is FindingStatus.SUSPECTED for finding in findings)
    assert any(finding.category is VulnerabilityCategory.SQL_INJECTION for finding in findings)
    assert any(finding.category is VulnerabilityCategory.COMMAND_INJECTION for finding in findings)
    assert ctx.diagnostics.heuristic_hits >= 7


async def test_llm_finding_with_valid_reference_is_accepted() -> None:
    """Verify a well-formed LLM finding referencing collected data passes."""
    provider = MockLLMProvider()
    provider.add_structured_response(SuspectedFindingsReport(findings=[_suspected()]))
    ctx = _inline_context(provider)

    findings = await DiscoveryAgent().run(ctx)

    semantic = [f for f in findings if not f.title.startswith("Heuristic match:")]
    assert len(semantic) == 1
    location = semantic[0].location
    assert location is not None
    assert location.file_path == "app.py"
    assert location.start_line == 3
    assert "rationale" in semantic[0].description


async def test_llm_reference_to_uncollected_file_is_dropped() -> None:
    """Verify paths outside the collection can never become findings."""
    provider = MockLLMProvider()
    provider.add_structured_response(
        SuspectedFindingsReport(findings=[_suspected(file_path="../../etc/passwd")])
    )
    ctx = _inline_context(provider)

    findings = await DiscoveryAgent().run(ctx)

    assert all(f.location.file_path == "app.py" for f in findings if f.location)
    assert ctx.diagnostics.dropped_references == 1


async def test_llm_line_past_end_of_file_is_dropped() -> None:
    """Verify line numbers beyond EOF are rejected."""
    provider = MockLLMProvider()
    provider.add_structured_response(SuspectedFindingsReport(findings=[_suspected(start_line=99)]))
    ctx = _inline_context(provider)

    findings = await DiscoveryAgent().run(ctx)

    assert all(not f.title.startswith("SQL injection") for f in findings)
    assert ctx.diagnostics.dropped_references == 1


async def test_llm_end_line_clamped_to_file_length() -> None:
    """Verify oversized end_line values are clamped to actual length."""
    provider = MockLLMProvider()
    provider.add_structured_response(
        SuspectedFindingsReport(findings=[_suspected(start_line=3, end_line=999)])
    )
    ctx = _inline_context(provider)

    findings = await DiscoveryAgent().run(ctx)

    semantic = [f for f in findings if not f.title.startswith("Heuristic match:")]
    assert semantic[0].location is not None
    assert semantic[0].location.end_line == 5


async def test_inverted_line_range_normalized() -> None:
    """Verify end < start collapses onto the start line."""
    provider = MockLLMProvider()
    provider.add_structured_response(
        SuspectedFindingsReport(findings=[_suspected(start_line=4, end_line=3)])
    )
    ctx = _inline_context(provider)

    findings = await DiscoveryAgent().run(ctx)

    semantic = [f for f in findings if not f.title.startswith("Heuristic match:")]
    assert semantic[0].location is not None
    assert semantic[0].location.end_line == 4


async def test_provider_failure_degrades_to_pure_heuristics() -> None:
    """Verify LLM outage still yields heuristic findings."""
    provider = MockLLMProvider()
    provider.set_error(ProviderExecutionError("rate limited"))
    ctx = _fixture_context(Path("."), provider)

    findings = await DiscoveryAgent().run(ctx)

    assert findings
    assert ctx.diagnostics.degraded is True


async def test_no_candidates_and_empty_llm_report_yields_nothing() -> None:
    """Verify benign inputs produce an empty result without errors."""
    provider = MockLLMProvider()
    empty_content = "x = 1\ny = x + 2\n"
    source = SourceFile(
        relative_path="clean.py",
        absolute_path=Path("clean.py"),
        size_bytes=len(empty_content),
        line_count=2,
        content=empty_content,
    )
    provider.add_structured_response(SuspectedFindingsReport())
    ctx = AgentContext(
        provider=provider,
        settings=MugiwaraSettings(),
        sources=CollectedSources(files=[source]),
        target_root=".",
    )

    findings = await DiscoveryAgent().run(ctx)

    assert findings == []
    assert ctx.diagnostics.degraded is False


async def test_semantic_finding_replaces_overlapping_heuristic_hit() -> None:
    """Verify identical (category, file, line) findings appear once."""
    provider = MockLLMProvider()
    provider.add_structured_response(SuspectedFindingsReport(findings=[_suspected()]))
    ctx = _inline_context(provider)

    findings = await DiscoveryAgent().run(ctx)

    assert len(findings) == 1
    assert findings[0].title == "SQL injection via f-string query"
    assert ctx.diagnostics.heuristic_hits == 1


def test_suspected_serialization_roundtrip() -> None:
    """Verify suspected findings serialize to JSON and back cleanly."""
    payload = SuspectedFindingsReport(findings=[_suspected()])
    raw = payload.model_dump_json()

    parsed = SuspectedFindingsReport.model_validate_json(raw)

    assert parsed.findings[0].file_path == "app.py"
