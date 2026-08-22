"""Vulnerability discovery agent: heuristic seeding plus semantic confirmation."""

from typing import ClassVar

from mugiwara.agents.base import AgentContext, BaseAgent
from mugiwara.agents.heuristics import scan_heuristics
from mugiwara.agents.models import (
    AttackSurfaceMap,
    HeuristicHit,
    SuspectedFinding,
    SuspectedFindingsReport,
)
from mugiwara.agents.sources import clamp_line_range
from mugiwara.core.exceptions import AgentExecutionError, MugiwaraError
from mugiwara.models.finding import Finding, FindingStatus, SourceLocation

_MAX_FINDINGS = 200

_MAX_CONTEXT_CHARS = 6_000


def _build_surface_block(surface: AttackSurfaceMap | None) -> str:
    """Render a compact stack/endpoint summary from the recon phase, if present."""
    if surface is None:
        return ""
    lines: list[str] = ["Detected technology context from reconnaissance:"]
    for component in surface.components[:20]:
        evidence = f" (evidence: {component.evidence_file})" if component.evidence_file else ""
        lines.append(f"- [{component.category}] {component.name}{evidence}")
    for endpoint in surface.endpoints[:30]:
        method = endpoint.method or "ANY"
        handler = f" -> {endpoint.handler_hint}" if endpoint.handler_hint else ""
        lines.append(f"- {method} {endpoint.path}{handler} ({endpoint.source_file})")
    return "\n".join(lines)


def _build_candidates_block(
    hits: list[HeuristicHit],
    ctx: AgentContext,
    max_snippet_chars: int,
) -> str:
    """Render heuristic hits with surrounding snippets into a prompt block.

    Snippets come exclusively from preloaded source content; the block is
    truncated once the character budget is consumed so prompts stay bounded.
    """
    if not hits:
        return _build_files_review_block(ctx, max_snippet_chars)
    blocks: list[str] = []
    used = 0
    for hit in hits:
        source = ctx.source_index.get(hit.file_path)
        if source is None:
            continue
        lines = source.content.splitlines()
        start = max(1, hit.line_number - 3)
        end = min(source.line_count, hit.line_number + 3)
        snippet_lines = [
            f"  {number}: {lines[number - 1].strip()}" for number in range(start, end + 1)
        ]
        snippet = "\n".join(snippet_lines)
        if len(snippet) > max_snippet_chars:
            snippet = snippet[:max_snippet_chars]
        block = (
            f"{hit.file_path}:{hit.line_number} [{hit.rule_id}] "
            f"({hit.severity.value}, {hit.cwe_id or 'no CWE'})\n"
            f"  matched: {hit.matched_line}\n{snippet}"
        )
        if used + len(block) > _MAX_CONTEXT_CHARS and blocks:
            break
        blocks.append(block)
        used += len(block)
    return "\n\n".join(blocks) if blocks else "(no candidate locations detected)"


def _build_files_review_block(ctx: AgentContext, max_snippet_chars: int) -> str:
    """Render collected file contents for review when no rules matched."""
    header = (
        "No deterministic rule matches were found. "
        "Review these collected files for high-confidence issues:"
    )
    parts: list[str] = [header]
    used = len(header)
    for source in ctx.sources.files:
        content = source.content
        if len(content) > max_snippet_chars:
            content = content[:max_snippet_chars]
        block = f"{source.relative_path} ({source.line_count} lines)\n{content}"
        if used + len(block) > _MAX_CONTEXT_CHARS and len(parts) > 1:
            break
        parts.append(block)
        used += len(block)
    return "\n\n".join(parts)


def _finding_from_hit(hit: HeuristicHit, ctx: AgentContext) -> Finding | None:
    """Convert a heuristic hit into a domain finding with a clamped location."""
    source = ctx.source_index.get(hit.file_path)
    if source is None:
        return None
    start = clamp_line_range(hit.line_number, None, source.line_count)
    if start is None:
        return None
    return Finding(
        title=f"Heuristic match: {hit.rule_id}",
        description=hit.message,
        category=hit.category,
        severity=hit.severity,
        cwe_id=hit.cwe_id,
        location=SourceLocation(
            file_path=hit.file_path,
            start_line=start,
            snippet=hit.matched_line,
        ),
    )


class DiscoveryAgent(BaseAgent):
    """Confirms heuristic candidates via LLM reasoning and emits findings."""

    _PROMPT_NAME: ClassVar[str] = "discovery.analysis"

    @property
    def name(self) -> str:
        """Return the agent identifier."""
        return "discovery"

    async def run(self, ctx: AgentContext) -> list[Finding]:
        """Run heuristics, request semantic confirmation, and confine output.

        The agent always emits at least the deterministic heuristic findings;
        LLM enrichment can only add candidates whose file paths exactly match
        files collected this session and whose line numbers fall inside those
        files. Anything else is dropped and counted.

        Args:
            ctx: Shared session context.

        Returns:
            Suspected domain findings ready for the report.
        """
        hits = scan_heuristics(ctx.sources.files)
        ctx.diagnostics.heuristic_hits = len(hits)

        findings: list[Finding] = []
        seen_keys: set[tuple[str, str, int]] = set()

        def try_add(finding: Finding) -> bool:
            key = (
                finding.category.value,
                finding.location.file_path if finding.location else "",
                finding.location.start_line if finding.location else 0,
            )
            if key in seen_keys or len(findings) >= _MAX_FINDINGS:
                return False
            seen_keys.add(key)
            findings.append(finding)
            return True

        llm_findings = await self._semantic_findings(ctx, hits)
        for finding in llm_findings:
            try_add(finding)
        for hit in hits:
            converted = _finding_from_hit(hit, ctx)
            if converted is not None:
                try_add(converted)
        return findings

    async def _semantic_findings(
        self,
        ctx: AgentContext,
        hits: list[HeuristicHit],
    ) -> list[Finding]:
        """Obtain LLM candidates and pass them through strict confinement."""
        candidates = _build_candidates_block(hits, ctx, ctx.settings.agents.max_snippet_chars)
        surface_block = _build_surface_block(ctx.attack_surface)
        block = f"{candidates}\n\n{surface_block}" if surface_block else candidates
        try:
            report = await self._request_structured(
                ctx,
                SuspectedFindingsReport,
                self._PROMPT_NAME,
                candidates_block=block,
            )
        except (AgentExecutionError, MugiwaraError) as exc:
            ctx.diagnostics.degraded = True
            ctx.diagnostics.errors.append(f"[{self.name}] degraded to heuristic-only: {exc}")
            return []

        confirmed: list[Finding] = []
        for suspected in report.findings:
            finding = self._confine(suspected, ctx)
            if finding is not None:
                confirmed.append(finding)
        return confirmed

    def _confine(self, suspected: SuspectedFinding, ctx: AgentContext) -> Finding | None:
        """Reject or clamp an LLM candidate against actually collected data.

        Returns None when the reference points to a file that was never
        collected; such output can never trigger a filesystem read here.
        """
        source = ctx.source_index.get(suspected.file_path)
        if source is None:
            ctx.diagnostics.dropped_references += 1
            return None
        start = clamp_line_range(suspected.start_line, suspected.end_line, source.line_count)
        if start is None:
            ctx.diagnostics.dropped_references += 1
            return None
        end_line = suspected.end_line
        if end_line is not None and end_line > source.line_count:
            end_line = source.line_count
        if end_line is not None and end_line < start:
            end_line = start
        snippet_lines = source.content.splitlines()
        snippet = snippet_lines[start - 1].strip()[:200] if start <= len(snippet_lines) else ""
        location = SourceLocation(
            file_path=suspected.file_path,
            start_line=start,
            end_line=end_line,
            snippet=snippet,
        )
        description = (
            f"{suspected.description}\n\nAnalyst rationale: {suspected.rationale}"
            if suspected.rationale
            else suspected.description
        )
        return Finding(
            title=suspected.title,
            description=description,
            category=suspected.category,
            severity=suspected.severity,
            cwe_id=suspected.cwe_id,
            status=FindingStatus.SUSPECTED,
            location=location,
        )
