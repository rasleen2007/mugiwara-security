"""Dynamic exploit verification agent: PoC synthesis, sandboxed execution, evaluation.

For each HTTP-reachable suspected finding, the agent asks the LLM for a minimal
non-destructive PoC probe, statically screens it (:mod:`mugiwara.agents.poc_safety`),
executes it inside a disposable sandbox against a staged copy of the target, and
maps the observed outcome onto a deterministic truth table. Only terminal outcomes
(VERIFIED / FALSE_POSITIVE) transition a finding out of SUSPECTED and attach an
:class:`~mugiwara.models.evidence.Evidence`; ambiguous runs leave the finding
untouched as UNVERIFIED or SKIPPED.
"""

import json
import re
from datetime import datetime, timezone
from typing import ClassVar

from pydantic import ValidationError

from mugiwara.agents.base import AgentContext, BaseAgent
from mugiwara.agents.discovery import _build_surface_block
from mugiwara.agents.models import VerificationOutcome, VerificationPlan
from mugiwara.agents.poc_safety import (
    CANARY_ENV_VAR,
    HTTP_TRACE_PREFIX,
    POC_LOG_MARKER,
    TARGET_LOG_MARKER,
    TARGET_URL_ENV_VAR,
    VERDICT_PREFIX,
    gen_canary_token,
    screen_poc,
)
from mugiwara.core.exceptions import (
    MugiwaraError,
    PocRejectedError,
    VerificationUnavailableError,
)
from mugiwara.models.evidence import Evidence, HTTPTrace
from mugiwara.models.finding import Finding, FindingStatus, VulnerabilityCategory
from mugiwara.sandbox.base import ExecResult

_VERIFIABLE_CATEGORIES = frozenset(
    {
        VulnerabilityCategory.SQL_INJECTION,
        VulnerabilityCategory.COMMAND_INJECTION,
        VulnerabilityCategory.CROSS_SITE_SCRIPTING,
        VulnerabilityCategory.PATH_TRAVERSAL,
        VulnerabilityCategory.REMOTE_CODE_EXECUTION,
    }
)

_ENTRY_CANDIDATES = ("app.py", "main.py", "server.py", "wsgi.py", "asgi.py", "manage.py")

_CONTAINER_PROBE_DIR = "/workspace/.mugiwara"

_DEFAULT_PORT = 5000

_LOG_SNIPPET_CHARS = 4_000

_EXIT_LINE_RE = re.compile(r"MUGIWARA_EXIT:(\d+)\s+READY:(\d+)")

_PORT_RE = re.compile(r"\bport\s*=\s*(\d{2,5})\b")

_TIMEOUT_SLACK_SECONDS = 5.0

_READINESS_SCRIPT = """\
import socket
import sys
import time

host = "127.0.0.1"
port = int(sys.argv[1])
wait = float(sys.argv[2])
deadline = time.time() + wait
while time.time() < deadline:
    try:
        with socket.create_connection((host, port), timeout=1):
            sys.exit(0)
    except OSError:
        time.sleep(0.25)
sys.exit(3)
"""


def _detect_entry_file(ctx: AgentContext) -> str | None:
    """Return the relative path of the most plausible application entrypoint."""
    names = {source.relative_path for source in ctx.sources.files}
    for candidate in _ENTRY_CANDIDATES:
        if candidate in names:
            return candidate
    ordered = sorted(ctx.sources.files, key=lambda source: source.relative_path.count("/"))
    for source in ordered:
        if source.relative_path.endswith(".py") and (
            "Flask(" in source.content or "FastAPI(" in source.content
        ):
            return source.relative_path
    return None


def _detect_port(ctx: AgentContext) -> int:
    """Infer the local bind port from collected sources, defaulting to 5000."""
    ordered = sorted(ctx.sources.files, key=lambda source: source.relative_path.count("/"))
    for source in ordered:
        match = _PORT_RE.search(source.content)
        if match:
            port = int(match.group(1))
            if 1024 <= port <= 65535:
                return port
    return _DEFAULT_PORT


def _is_reachable(finding: Finding, ctx: AgentContext) -> bool:
    """Return True when the finding's file is referenced by a recon endpoint."""
    surface = ctx.attack_surface
    if surface is None or not surface.endpoints or finding.location is None:
        return False
    return any(endpoint.source_file == finding.location.file_path for endpoint in surface.endpoints)


def _select_candidates(ctx: AgentContext) -> tuple[list[Finding], int]:
    """Pick verifiable candidates and report how many were dropped as unreachable."""
    candidates = [
        finding
        for finding in ctx.findings
        if finding.status is FindingStatus.SUSPECTED
        and finding.location is not None
        and finding.category in _VERIFIABLE_CATEGORIES
    ]
    reachable = [finding for finding in candidates if _is_reachable(finding, ctx)]
    return reachable, len(candidates) - len(reachable)


def _build_harness(entry_rel_path: str, probe_container_path: str, port: int, wait: int) -> str:
    """Assemble the composite sh harness run inside one exec_command call."""
    entry_container_path = f"/workspace/{entry_rel_path}"
    readiness_path = f"{_CONTAINER_PROBE_DIR}/readiness.py"
    return (
        f"cd /workspace || exit 90\n"
        f"python3 '{entry_container_path}' > /tmp/mg_target.log 2>&1 &\n"
        f"MG_APP_PID=$!\n"
        f"python3 '{readiness_path}' {port} {wait} > /dev/null 2>&1\n"
        f"MG_READY=$?\n"
        f"python3 '{probe_container_path}' > /tmp/mg_poc.log 2>&1\n"
        f"MG_RC=$?\n"
        f"kill $MG_APP_PID > /dev/null 2>&1\n"
        f'echo "{TARGET_LOG_MARKER}"\n'
        f"cat /tmp/mg_target.log 2> /dev/null || true\n"
        f'echo "{POC_LOG_MARKER}"\n'
        f"cat /tmp/mg_poc.log 2> /dev/null || true\n"
        f'echo "MUGIWARA_EXIT:$MG_RC READY:$MG_READY"\n'
    )


class _HarnessOutput:
    """Parsed sections of one composite harness execution."""

    def __init__(self, stdout: str) -> None:
        self.target_log = ""
        self.poc_log = ""
        self.exit_code: int | None = None
        self.ready_ok = False
        if TARGET_LOG_MARKER in stdout and POC_LOG_MARKER in stdout:
            after_target = stdout.split(TARGET_LOG_MARKER, 1)[1]
            poc_section = after_target.split(POC_LOG_MARKER, 1)
            self.target_log = poc_section[0].strip("\r\n")
            remainder = poc_section[1] if len(poc_section) > 1 else ""
            lines = remainder.splitlines()
            log_lines: list[str] = []
            for line in lines:
                match = _EXIT_LINE_RE.search(line)
                if match:
                    self.exit_code = int(match.group(1))
                    self.ready_ok = int(match.group(2)) == 0
                else:
                    log_lines.append(line)
            self.poc_log = "\n".join(log_lines).strip("\r\n")


def _extract_verdict(poc_log: str) -> dict[str, object] | None:
    """Parse the final MUGIWARA_VERDICT JSON line, returning None when absent/malformed."""
    verdict_line: str | None = None
    for line in poc_log.splitlines():
        stripped = line.strip()
        if stripped.startswith(VERDICT_PREFIX):
            verdict_line = stripped[len(VERDICT_PREFIX) :]
    if verdict_line is None:
        return None
    try:
        parsed = json.loads(verdict_line)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


def _extract_http_trace(poc_log: str) -> HTTPTrace | None:
    """Build an HTTPTrace from the structured trace line emitted by the probe."""
    trace_line: str | None = None
    for line in poc_log.splitlines():
        stripped = line.strip()
        if stripped.startswith(HTTP_TRACE_PREFIX):
            trace_line = stripped[len(HTTP_TRACE_PREFIX) :]
    if trace_line is None:
        return None
    try:
        raw = json.loads(trace_line)
        method = str(raw["method"]).upper()
        url = str(raw["url"])
        status_raw = raw.get("http_status")
        status = int(status_raw) if status_raw is not None else None
        snippet = raw.get("response_body_snippet")
        body_snippet = str(snippet)[:500] if snippet is not None else None
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None
    try:
        return HTTPTrace(
            method=method,
            url=url,
            response_status_code=status,
            response_body_snippet=body_snippet,
        )
    except ValidationError:
        return None


class VerificationAgent(BaseAgent):
    """Synthesizes, screens, executes, and evaluates non-destructive PoC probes."""

    PROMPT_NAME: ClassVar[str] = "verification.synthesis"

    @property
    def name(self) -> str:
        """Return the agent identifier."""
        return "verification"

    async def run(self, ctx: AgentContext) -> list[Finding]:
        """Verify HTTP-reachable suspected findings via sandboxed PoC execution.

        Args:
            ctx: Shared session context carrying findings, sandbox, and staging.

        Returns:
            The findings processed this phase (terminal or inconclusive).

        Raises:
            VerificationUnavailableError: If no sandbox or staging workspace
                has been attached to the context.
        """
        sandbox = ctx.sandbox
        staging = ctx.staging
        if sandbox is None or staging is None:
            msg = "Dynamic verification requires an attached sandbox and staging workspace."
            raise VerificationUnavailableError(msg)

        config = ctx.settings.verification
        diagnostics = ctx.diagnostics
        diagnostics.sandbox_backend = sandbox.backend_name
        diagnostics.staging_files = staging.file_count()

        candidates, unreachable = _select_candidates(ctx)
        diagnostics.verification_candidates = len(candidates)
        if unreachable:
            diagnostics.errors.append(
                f"[{self.name}] skipped {unreachable} candidate(s): "
                "no recon-declared HTTP endpoint references their file."
            )

        selected = candidates[: config.max_poc_executions]
        if len(selected) < len(candidates):
            diagnostics.errors.append(
                f"[{self.name}] budget capped verification at {len(selected)} of "
                f"{len(candidates)} candidates."
            )

        entry_rel_path = _detect_entry_file(ctx)
        port = _detect_port(ctx)

        processed: list[Finding] = []
        for expected_ref, finding in enumerate(selected):
            processed.append(finding)
            outcome = await self._verify_candidate(
                ctx,
                finding,
                expected_ref=expected_ref,
                entry_rel_path=entry_rel_path,
                port=port,
            )
            if outcome is VerificationOutcome.VERIFIED:
                diagnostics.verification_verified += 1
            elif outcome is VerificationOutcome.FALSE_POSITIVE:
                diagnostics.verification_false_positives += 1
            elif outcome is VerificationOutcome.UNVERIFIED:
                diagnostics.verification_unverified += 1
        return processed

    async def _verify_candidate(
        self,
        ctx: AgentContext,
        finding: Finding,
        *,
        expected_ref: int,
        entry_rel_path: str | None,
        port: int,
    ) -> VerificationOutcome:
        """Run synthesis, screening, execution, and evaluation for one candidate."""
        return await self._synthesize_and_execute(ctx, finding, expected_ref, entry_rel_path, port)

    async def _synthesize_and_execute(
        self,
        ctx: AgentContext,
        finding: Finding,
        expected_ref: int,
        entry_rel_path: str | None,
        port: int,
    ) -> VerificationOutcome:
        """Perform the full per-candidate pipeline."""
        config = ctx.settings.verification
        diagnostics = ctx.diagnostics
        canary = gen_canary_token()
        finding_block = self._build_finding_block(finding)
        surface_block = _build_surface_block(ctx.attack_surface) or "(no endpoints detected)"

        try:
            plan = await self._request_structured(
                ctx,
                VerificationPlan,
                self.PROMPT_NAME,
                finding_block=finding_block,
                surface_block=surface_block,
            )
        except MugiwaraError as exc:
            diagnostics.degraded = True
            diagnostics.errors.append(
                f"[{self.name}] synthesis failed for '{finding.title}': {exc}"
            )
            return VerificationOutcome.UNVERIFIED

        if plan.finding_ref != expected_ref:
            diagnostics.dropped_references += 1
            diagnostics.errors.append(
                f"[{self.name}] plan referenced finding_ref={plan.finding_ref}, "
                f"expected {expected_ref}; rejected."
            )
            return VerificationOutcome.UNVERIFIED

        try:
            self._screen_or_raise(plan.poc_script, config.max_poc_bytes)
        except PocRejectedError as exc:
            diagnostics.dropped_references += 1
            diagnostics.errors.append(str(exc))
            return VerificationOutcome.UNVERIFIED

        if entry_rel_path is None:
            diagnostics.errors.append(
                f"[{self.name}] skipped '{finding.title}': no runnable entrypoint detected."
            )
            return VerificationOutcome.SKIPPED

        assert ctx.sandbox is not None
        assert ctx.staging is not None
        probe_name = f"poc_{expected_ref}.py"
        ctx.staging.write_probe(probe_name, plan.poc_script)
        ctx.staging.write_probe("readiness.py", _READINESS_SCRIPT)
        probe_container_path = f"{_CONTAINER_PROBE_DIR}/{probe_name}"

        harness = _build_harness(
            entry_rel_path,
            probe_container_path,
            port,
            min(plan.max_readiness_wait_seconds, config.readiness_wait_seconds),
        )
        environment = {
            TARGET_URL_ENV_VAR: f"http://127.0.0.1:{port}",
            CANARY_ENV_VAR: canary,
        }
        timeout = (
            config.poc_timeout_seconds
            + float(config.readiness_wait_seconds)
            + _TIMEOUT_SLACK_SECONDS
        )
        try:
            exec_result = await ctx.sandbox.exec_command(
                ["sh", "-c", harness],
                timeout_seconds=timeout,
                environment=environment,
                workdir="/workspace",
            )
        except MugiwaraError as exc:
            diagnostics.degraded = True
            diagnostics.errors.append(
                f"[{self.name}] sandbox execution failed for '{finding.title}': {exc}"
            )
            return VerificationOutcome.UNVERIFIED

        diagnostics.verification_attempted += 1
        return await self._evaluate_and_record(ctx, finding, plan, exec_result, canary)

    async def _evaluate_and_record(
        self,
        ctx: AgentContext,
        finding: Finding,
        plan: VerificationPlan,
        exec_result: ExecResult,
        canary: str,
    ) -> VerificationOutcome:
        """Map one execution result onto the deterministic truth table."""
        output = _HarnessOutput(exec_result.stdout)
        combined = f"{output.poc_log}\n{output.target_log}"
        canary_observed = canary in combined

        if exec_result.timed_out or exec_result.exit_code is None:
            return self._note(ctx, finding, "probe execution timed out.")
        if output.exit_code is None:
            return self._note(ctx, finding, "harness produced no exit marker.")
        if not output.ready_ok:
            return self._note(ctx, finding, "target failed its readiness wait.")

        verdict = _extract_verdict(output.poc_log)
        if verdict is None:
            return self._note(ctx, finding, "probe produced no parsable verdict line.")

        claimed = bool(verdict.get("canary_found", False))
        if claimed and canary_observed:
            self._attach_evidence(ctx, finding, plan, exec_result, output, True, canary)
            finding.status = FindingStatus.VERIFIED
            return VerificationOutcome.VERIFIED
        if claimed:
            return self._note(ctx, finding, "verdict claimed canary but token was never echoed.")
        if output.exit_code == 0:
            self._attach_evidence(ctx, finding, plan, exec_result, output, False, canary)
            finding.status = FindingStatus.FALSE_POSITIVE
            return VerificationOutcome.FALSE_POSITIVE
        return self._note(ctx, finding, "probe exited nonzero while claiming a clean result.")

    def _note(self, ctx: AgentContext, finding: Finding, reason: str) -> VerificationOutcome:
        """Record an inconclusive outcome without touching finding status."""
        ctx.diagnostics.errors.append(f"[{self.name}] '{finding.title}' unverified: {reason}")
        return VerificationOutcome.UNVERIFIED

    def _screen_or_raise(self, script: str, max_bytes: int) -> None:
        """Screen a synthesized PoC, raising PocRejectedError on any violation."""
        result = screen_poc(script, max_bytes=max_bytes)
        if not result.allowed:
            msg = f"[{self.name}] PoC rejected by safety screening: {'; '.join(result.reasons)}"
            raise PocRejectedError(msg)

    def _build_finding_block(self, finding: Finding) -> str:
        """Render one suspected finding into a bounded prompt block."""
        location = finding.location
        loc_text = (
            f"{location.file_path}:{location.start_line}"
            if location is not None
            else "(unknown location)"
        )
        cwe = finding.cwe_id or "none"
        description = finding.description[:800]
        raw_snippet = (location.snippet if location is not None else "") or ""
        snippet = raw_snippet[:200]
        return (
            f"title: {finding.title}\n"
            f"category: {finding.category.value}\n"
            f"severity: {finding.severity.value}\n"
            f"cwe: {cwe}\n"
            f"location: {loc_text}\n"
            f"snippet: {snippet}\n"
            f"description: {description}"
        )

    def _attach_evidence(
        self,
        ctx: AgentContext,
        finding: Finding,
        plan: VerificationPlan,
        exec_result: ExecResult,
        output: _HarnessOutput,
        canary_found: bool,
        canary: str,
    ) -> None:
        """Attach a complete Evidence record to a terminally evaluated finding."""
        finding.evidence = Evidence(
            poc_script=plan.poc_script,
            reproduction_steps=plan.reproduction_steps,
            http_trace=_extract_http_trace(output.poc_log),
            stdout_log=output.target_log[:_LOG_SNIPPET_CHARS] or None,
            stderr_log=output.poc_log[:_LOG_SNIPPET_CHARS] or None,
            canary_found=canary_found,
            canary_token=canary,
            verified_at=datetime.now(timezone.utc),
            sandbox_runtime_seconds=round(exec_result.duration_seconds, 3),
        )
