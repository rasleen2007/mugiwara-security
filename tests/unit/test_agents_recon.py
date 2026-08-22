"""Unit tests for the reconnaissance agent with a mock LLM provider."""

from pathlib import Path

from mugiwara.agents.base import AgentContext
from mugiwara.agents.models import AttackSurfaceMap, TechStackComponent
from mugiwara.agents.recon import ReconAgent
from mugiwara.agents.sources import CollectedSources, SourceFile, WorkspaceCollector
from mugiwara.core.config import AgentConfig, MugiwaraSettings
from mugiwara.core.exceptions import ProviderExecutionError
from mugiwara.providers.mock import MockLLMProvider

FIXTURE_APP = Path(__file__).resolve().parents[1] / "fixtures" / "sample_vulnerable_app"


def _context(tmp_path: Path, provider: MockLLMProvider) -> AgentContext:
    """Collect the fixture app and build a context around it."""
    settings = MugiwaraSettings()
    sources = WorkspaceCollector(AgentConfig()).collect(FIXTURE_APP)
    return AgentContext(
        provider=provider,
        settings=settings,
        sources=sources,
        target_root=str(tmp_path),
    )


def _source(content: str, name: str = "routes.py") -> SourceFile:
    """Build an inline SourceFile."""
    return SourceFile(
        relative_path=name,
        absolute_path=Path(name),
        size_bytes=len(content),
        line_count=len(content.splitlines()),
        content=content,
    )


async def test_heuristic_map_detects_fixture_stack_and_routes(tmp_path: Path) -> None:
    """Verify deterministic detection of framework, database, and routes."""
    provider = MockLLMProvider()
    ctx = _context(tmp_path, provider)

    surface = await ReconAgent().run(ctx)

    component_names = {component.name for component in surface.components}
    assert "Flask" in component_names
    assert "SQLite" in component_names
    route_pairs = {(endpoint.path, endpoint.method) for endpoint in surface.endpoints}
    assert ("/users", None) in route_pairs
    assert ("/ping", "POST") in route_pairs


async def test_flask_route_with_methods_list_parses_method() -> None:
    """Verify @app.route(..., methods=['POST']) captures the method."""
    provider = MockLLMProvider()
    content = "\n".join(
        [
            "from flask import Flask",
            "app = Flask(__name__)",
            "@app.route('/submit', methods=['POST'])",
            "def submit():",
            "    return 'ok'",
        ]
    )
    ctx = AgentContext(
        provider=provider,
        settings=MugiwaraSettings(),
        sources=CollectedSources(files=[_source(content)]),
        target_root=".",
    )

    surface = await ReconAgent().run(ctx)

    endpoint = surface.endpoints[0]
    assert (endpoint.path, endpoint.method, endpoint.handler_hint) == (
        "/submit",
        "POST",
        "submit",
    )
    assert endpoint.source_file == "routes.py"


async def test_llm_enrichment_merges_into_heuristic_map(tmp_path: Path) -> None:
    """Verify LLM components/endpoints merge without duplicating heuristics."""
    provider = MockLLMProvider()
    provider.add_structured_response(
        AttackSurfaceMap(
            components=[
                TechStackComponent(name="flask", category="framework", confidence=0.95),
                TechStackComponent(name="Redis", category="database"),
            ],
            summary="Small Flask service.",
        )
    )
    ctx = _context(tmp_path, provider)

    surface = await ReconAgent().run(ctx)

    frameworks = [c for c in surface.components if c.category == "framework"]
    assert any(c.name == "Flask" for c in frameworks)
    assert len([c for c in frameworks if c.name.lower() == "flask"]) == 1
    databases = {c.name for c in surface.components if c.category == "database"}
    assert databases == {"SQLite", "Redis"}
    assert surface.summary == "Small Flask service."


async def test_invalid_llm_reference_is_stripped_not_followed(tmp_path: Path) -> None:
    """Verify evidence paths outside collected files are dropped and counted."""
    provider = MockLLMProvider()
    provider.add_structured_response(
        AttackSurfaceMap(
            components=[
                TechStackComponent(
                    name="Phantom",
                    category="framework",
                    evidence_file="/etc/passwd",
                )
            ],
        )
    )
    ctx = _context(tmp_path, provider)

    surface = await ReconAgent().run(ctx)

    phantom = next(c for c in surface.components if c.name == "Phantom")
    assert phantom.evidence_file is None
    assert ctx.diagnostics.dropped_references >= 1
    assert "/etc/passwd" not in str(surface.model_dump())


async def test_provider_failure_degrades_to_heuristic_only(tmp_path: Path) -> None:
    """Verify LLM failure yields the heuristic map with degraded diagnostics."""
    provider = MockLLMProvider()
    provider.set_error(ProviderExecutionError("provider offline"))
    ctx = _context(tmp_path, provider)

    surface = await ReconAgent().run(ctx)

    assert surface.endpoints, "heuristic routes must survive LLM failure"
    assert ctx.diagnostics.degraded is True
    assert any("degraded" in error.lower() for error in ctx.diagnostics.errors)


async def test_budget_records_estimated_tokens_after_success(tmp_path: Path) -> None:
    """Verify token accounting increases after a successful structured call."""
    provider = MockLLMProvider()
    provider.add_structured_response(AttackSurfaceMap())
    ctx = _context(tmp_path, provider)

    await ReconAgent().run(ctx)

    assert ctx.diagnostics.llm_calls >= 1
    assert ctx.budget.used_tokens > 0
    assert ctx.diagnostics.tokens_used == ctx.budget.used_tokens


async def test_exhausted_budget_degrades_without_crash() -> None:
    """Verify budget exhaustion during recon degrades to heuristic-only."""
    provider = MockLLMProvider()
    settings = MugiwaraSettings()
    settings.agents.max_total_tokens = 1
    sources = WorkspaceCollector(AgentConfig()).collect(FIXTURE_APP)
    ctx = AgentContext(
        provider=provider,
        settings=settings,
        sources=sources,
        target_root=".",
    )

    surface = await ReconAgent().run(ctx)

    assert surface.endpoints
    assert ctx.diagnostics.degraded is True
