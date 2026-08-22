"""Reconnaissance agent: tech-stack detection and attack surface mapping."""

import re
from typing import ClassVar

from mugiwara.agents.base import AgentContext, BaseAgent
from mugiwara.agents.models import AttackSurfaceMap, Endpoint, TechStackComponent
from mugiwara.agents.sources import clamp_single_line
from mugiwara.core.exceptions import AgentExecutionError, MugiwaraError

_ROUTE_PATTERN = re.compile(
    r"@(?:app|router|blueprint|api)\.(get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]*)['\"]"
)
_FLASK_ROUTE_PATTERN = re.compile(r"@(?:app|router|blueprint)\.route\s*\(\s*['\"]([^'\"]*)['\"]")
_FLASK_METHODS_PATTERN = re.compile(r"methods\s*=\s*\[\s*['\"]([A-Za-z]+)['\"]")

_FRAMEWORK_SIGNALS: tuple[tuple[str, str], ...] = (
    ("from fastapi", "FastAPI"),
    ("from flask", "Flask"),
    ("django", "Django"),
    ("express", "Express"),
    ("@SpringBootApplication", "Spring Boot"),
    ("Rails.application", "Ruby on Rails"),
)

_DATABASE_SIGNALS: tuple[tuple[str, str], ...] = (
    ("sqlalchemy", "SQLAlchemy"),
    ("sqlite3", "SQLite"),
    ("psycopg2", "PostgreSQL"),
    ("psycopg", "PostgreSQL"),
    ("mysql.connector", "MySQL"),
    ("mongoose", "MongoDB"),
    ("redis", "Redis"),
)


def _detect_frameworks(ctx: AgentContext) -> list[TechStackComponent]:
    """Detect frameworks from collected file contents using fixed signal strings."""
    components: list[TechStackComponent] = []
    seen: set[str] = set()
    for source in ctx.sources.files:
        lowered = source.content.lower()
        for needle, framework in _FRAMEWORK_SIGNALS:
            if needle in lowered and framework not in seen:
                seen.add(framework)
                components.append(
                    TechStackComponent(
                        name=framework,
                        category="framework",
                        confidence=0.9,
                        evidence_file=source.relative_path,
                    )
                )
    return components


def _detect_databases(ctx: AgentContext) -> list[TechStackComponent]:
    """Detect database client libraries from imports in collected files."""
    components: list[TechStackComponent] = []
    seen: set[str] = set()
    for source in ctx.sources.files:
        lowered = source.content.lower()
        for needle, database in _DATABASE_SIGNALS:
            if needle in lowered and database not in seen:
                seen.add(database)
                components.append(
                    TechStackComponent(
                        name=database,
                        category="database",
                        confidence=0.7,
                        evidence_file=source.relative_path,
                    )
                )
    return components


def _detect_languages(ctx: AgentContext) -> list[TechStackComponent]:
    """Summarize detected languages from collected file extensions."""
    counts: dict[str, int] = {}
    for source in ctx.sources.files:
        relative = source.relative_path
        suffix = "." + relative.rsplit(".", 1)[-1] if "." in relative else ""
        counts[suffix] = counts.get(suffix, 0) + 1
    language_names = {".py": "Python", ".js": "JavaScript", ".ts": "TypeScript"}
    components: list[TechStackComponent] = []
    for suffix, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        name = language_names.get(suffix)
        if name is not None:
            components.append(
                TechStackComponent(
                    name=name,
                    category="language",
                    confidence=min(1.0, 0.5 + count / 10),
                )
            )
    return components


def _handler_name(line: str) -> str | None:
    """Extract the function identifier from a ``def``/``async def`` line."""
    head = line.split("(", 1)[0]
    tokens = head.replace("async", "").split()
    return tokens[-1] if len(tokens) >= 2 else None


def _heuristic_endpoints(ctx: AgentContext) -> list[Endpoint]:
    """Extract route declarations via decorators in Python sources.

    A pending route is claimed by the next function definition; an unclaimed
    route is still reported, and a second route declaration supersedes an
    unclaimed predecessor.
    """
    endpoints: list[Endpoint] = []
    for source in ctx.sources.files:
        if not source.relative_path.endswith(".py"):
            continue
        pending: Endpoint | None = None
        for line_number, line in enumerate(source.content.splitlines(), start=1):
            verb_match = _ROUTE_PATTERN.search(line)
            if verb_match is not None:
                if pending is not None:
                    endpoints.append(pending)
                pending = Endpoint(
                    path=verb_match.group(2),
                    method=verb_match.group(1).upper(),
                    source_file=source.relative_path,
                    line_number=line_number,
                )
                continue
            route_match = _FLASK_ROUTE_PATTERN.search(line)
            if route_match is not None:
                if pending is not None:
                    endpoints.append(pending)
                methods_match = _FLASK_METHODS_PATTERN.search(line)
                method = methods_match.group(1).upper() if methods_match else None
                pending = Endpoint(
                    path=route_match.group(1),
                    method=method,
                    source_file=source.relative_path,
                    line_number=line_number,
                )
                continue
            stripped = line.strip()
            if pending is not None and (
                stripped.startswith("def ") or stripped.startswith("async def ")
            ):
                handler = _handler_name(stripped)
                if handler is not None:
                    pending = pending.model_copy(update={"handler_hint": handler})
                endpoints.append(pending)
                pending = None
        if pending is not None:
            endpoints.append(pending)
    return endpoints


class ReconAgent(BaseAgent):
    """Maps technologies and exposed endpoints for the scanned codebase."""

    _PROMPT_NAME: ClassVar[str] = "recon.analysis"

    @property
    def name(self) -> str:
        """Return the agent identifier."""
        return "recon"

    async def run(self, ctx: AgentContext) -> AttackSurfaceMap:
        """Produce the attack surface map.

        Static heuristics always run first; the LLM then enriches the map.
        Any LLM-side failure degrades gracefully to the heuristic-only map
        instead of failing the session.

        Args:
            ctx: Shared session context.

        Returns:
            The merged attack surface map.
        """
        base_map = self._heuristic_map(ctx)
        file_listing = (
            "\n".join(
                f"- {source.relative_path} ({source.size_bytes} bytes)"
                for source in ctx.sources.files
            )
            or "(no files collected)"
        )
        route_hints = (
            "\n".join(
                f"- {endpoint.method or 'ANY'} {endpoint.path} "
                f"({endpoint.source_file}:{endpoint.line_number})"
                for endpoint in base_map.endpoints
            )
            or "(none detected)"
        )
        stack_hints = (
            "\n".join(
                f"- [{component.category}] {component.name}" for component in base_map.components
            )
            or "(none detected)"
        )
        secret_hints = (
            "\n".join(f"- {marker}" for marker in ctx.sources.secret_markers) or "(none detected)"
        )

        try:
            llm_map = await self._request_structured(
                ctx,
                AttackSurfaceMap,
                self._PROMPT_NAME,
                target_root=ctx.target_root,
                file_listing=file_listing,
                route_hints=route_hints,
                stack_hints=stack_hints,
                secret_hints=secret_hints,
            )
        except (AgentExecutionError, MugiwaraError) as exc:
            ctx.diagnostics.degraded = True
            ctx.diagnostics.errors.append(f"[{self.name}] degraded to heuristic-only map: {exc}")
            return base_map

        return self._merge(base_map, llm_map, ctx)

    def _heuristic_map(self, ctx: AgentContext) -> AttackSurfaceMap:
        """Build the purely deterministic portion of the map."""
        components = [
            *_detect_languages(ctx),
            *_detect_frameworks(ctx),
            *_detect_databases(ctx),
        ]
        return AttackSurfaceMap(components=components, endpoints=_heuristic_endpoints(ctx))

    def _merge(
        self,
        base_map: AttackSurfaceMap,
        llm_map: AttackSurfaceMap,
        ctx: AgentContext,
    ) -> AttackSurfaceMap:
        """Merge LLM output into the heuristic map with strict confinement.

        LLM-supplied evidence paths and route locations are accepted only when
        they reference files actually collected this session; invalid
        references are stripped and counted, never followed.
        """
        merged_components: dict[tuple[str, str], TechStackComponent] = {
            (component.name.lower(), component.category): component
            for component in base_map.components
        }
        for component in llm_map.components:
            key = (component.name.lower(), component.category)
            evidence = component.evidence_file
            if evidence is not None and evidence not in ctx.source_paths:
                component = component.model_copy(update={"evidence_file": None})
                ctx.diagnostics.dropped_references += 1
            if key in merged_components:
                existing = merged_components[key]
                if existing.evidence_file is None and component.evidence_file is not None:
                    merged_components[key] = component
            else:
                merged_components[key] = component

        merged_endpoints: dict[tuple[str, str | None], Endpoint] = {
            (endpoint.path, endpoint.method): endpoint for endpoint in base_map.endpoints
        }
        for endpoint in llm_map.endpoints:
            source_file = endpoint.source_file
            line_number = endpoint.line_number
            valid_reference = True
            if source_file is not None:
                target = ctx.source_index.get(source_file)
                if target is None:
                    valid_reference = False
                    ctx.diagnostics.dropped_references += 1
                else:
                    line_number = clamp_single_line(line_number, target.line_count)
                    if endpoint.line_number is not None and line_number is None:
                        valid_reference = False
                        ctx.diagnostics.dropped_references += 1
            if not valid_reference:
                endpoint = endpoint.model_copy(update={"source_file": None, "line_number": None})
            endpoint_key = (endpoint.path, endpoint.method)
            if endpoint_key not in merged_endpoints:
                merged_endpoints[endpoint_key] = endpoint

        summary = llm_map.summary
        return AttackSurfaceMap(
            components=sorted(merged_components.values(), key=lambda c: (c.category, c.name)),
            endpoints=sorted(
                merged_endpoints.values(),
                key=lambda e: (e.source_file or "", e.line_number or 0, e.path),
            ),
            summary=summary,
        )
