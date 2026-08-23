"""Remediation orchestration: propose -> confine -> apply (isolated) -> sea trial.

The service deliberately rides the exact rails built in Phase 4: the scan
pipeline (:class:`~mugiwara.agents.orchestrator.ScanOrchestrator`) produces
dynamically verified findings with attached PoC evidence; the disposable
:class:`~mugiwara.agents.staging.StagingWorkspace` is the only surface patches
are ever applied to; and the composite harness helpers from
:mod:`mugiwara.agents.verification` boot the patched target and execute the
ORIGINAL proof-of-concept verbatim, with the ORIGINAL canary token. A fix is
only ``VERIFIED_FIXED`` when that rerun demonstrably stops reproducing the
exploit; every inconclusive or broken outcome is honestly reported.
"""

import asyncio
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar

from pydantic import BaseModel, Field

from mugiwara.agents.base import AgentContext, BaseAgent
from mugiwara.agents.models import AgentDiagnostics, RemediationPlan
from mugiwara.agents.orchestrator import ScanOrchestrator, ScanRunResult
from mugiwara.agents.poc_safety import (
    CANARY_ENV_VAR,
    HTTP_TRACE_PREFIX,
    TARGET_URL_ENV_VAR,
    VERDICT_PREFIX,
)
from mugiwara.agents.sources import CollectedSources, SourceFile, WorkspaceCollector
from mugiwara.agents.staging import StagingWorkspace
from mugiwara.agents.verification import (
    _CONTAINER_PROBE_DIR,
    _READINESS_SCRIPT,
    _TIMEOUT_SLACK_SECONDS,
    _build_harness,
    _detect_entry_file,
    _detect_port,
    _extract_http_trace,
    _extract_verdict,
    _HarnessOutput,
    _readiness_failure_reason,
)
from mugiwara.core.config import MugiwaraSettings
from mugiwara.core.exceptions import (
    MugiwaraError,
    ReportTargetMismatchError,
    TargetPathError,
)
from mugiwara.models.evidence import Evidence, HTTPTrace
from mugiwara.models.finding import Finding, FindingStatus
from mugiwara.models.remediation import (
    RemediationRecord,
    RemediationReport,
    RemediationStatus,
)
from mugiwara.providers.factory import get_provider
from mugiwara.remediation.patches import (
    build_unified_diff,
    sha256_text,
    validate_python_source,
)
from mugiwara.reports.store import StoredScanReport
from mugiwara.sandbox.base import BaseSandbox, ExecResult, WorkspaceMount
from mugiwara.sandbox.factory import get_sandbox

_POSTFIX_PROBE_NAME = "poc_postfix_rerun.py"

_LOG_SNIPPET_CHARS = 4_000

_POC_BLOCK_CHARS = 2_000

_DEFAULT_MAX_FINDINGS = 5


def _utcnow() -> datetime:
    """Return the current aware UTC timestamp."""
    return datetime.now(timezone.utc)


def _location_text(finding: Finding) -> str | None:
    """Render 'path:line' for a finding location, or None."""
    location = finding.location
    if location is None:
        return None
    return f"{location.file_path}:{location.start_line}"


def _build_finding_block(finding: Finding) -> str:
    """Render one verified finding into a bounded prompt block."""
    cwe = finding.cwe_id or "none"
    description = finding.description[:800]
    return (
        f"title: {finding.title}\n"
        f"category: {finding.category.value}\n"
        f"severity: {finding.severity.value}\n"
        f"cwe: {cwe}\n"
        f"file_path: {_location_text(finding) or '(unknown)'}\n"
        f"description: {description}"
    )


def _build_source_block(source_file: SourceFile) -> str:
    """Wrap the vulnerable file content with the sentinel markers."""
    return (
        f"file_path: {source_file.relative_path}\n"
        "---BEGIN VULNERABLE SOURCE---\n"
        f"{source_file.content}\n"
        "---END VULNERABLE SOURCE---"
    )


def _newline_normalized(text: str) -> str:
    """Return the canonical LF-only representation of collected source text.

    Source collection preserves the file's on-disk line endings, so on
    Windows a target authored with CRLF is stored verbatim. Records and
    unified diffs must stay platform-independent and readable (no stray
    carriage returns), and no-op detection must not mistake a pure
    newline conversion for a remediation. Every consumer in the
    remediation path therefore works against this normalized form; the
    user's original file on disk is never rewritten.
    """
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _attacker_visible_output(poc_log: str, trace: HTTPTrace | None) -> str:
    """Extract only the data the attacker's PoC actually RECEIVED back.

    Canary observation means "the exploit returned the payload to the
    attacker". Two transcript line types describe the attempt instead of
    returning data and must never count as observation:

    * ``MUGIWARA_HTTP_TRACE`` embeds the request URL, which legitimately
      contains the payload that was SENT;
    * ``MUGIWARA_VERDICT`` is the probe's boolean CLAIM.

    The target's server-side log is operator telemetry, not an
    attacker-readable channel: Werkzeug-style access logs echo the full
    request line (payload included) even for correctly patched targets.
    Observation therefore requires the token inside free-form PoC output
    (body snippets the probe printed) or inside the structured HTTP
    response body snippet.
    """
    received_lines = [
        line
        for line in poc_log.splitlines()
        if not line.strip().startswith((VERDICT_PREFIX, HTTP_TRACE_PREFIX))
    ]
    visible = "\n".join(received_lines)
    if trace is not None and trace.response_body_snippet:
        visible += f"\n{trace.response_body_snippet}"
    return visible


class RemediationAgent(BaseAgent):
    """LLM-backed agent proposing confined full-file remediation patches."""

    PROMPT_NAME: ClassVar[str] = "remediation.patch"

    @property
    def name(self) -> str:
        """Return the agent identifier."""
        return "remediation"

    @property
    def prompt_name(self) -> str:
        """Return the registered template key."""
        return self.PROMPT_NAME

    async def run(self, ctx: AgentContext) -> Any:
        """Execute the remediation agent phase.

        Remediation is coordinated per finding by ``RemediationService``;
        this entry point exists to satisfy the shared ``BaseAgent`` contract.
        """
        return None

    async def propose_plan(
        self,
        ctx: AgentContext,
        finding: Finding,
        expected_ref: int,
        source_file: SourceFile,
        evidence: Evidence,
    ) -> RemediationPlan:
        """Request a schema-validated RemediationPlan for one verified finding."""
        poc_text = (evidence.poc_script or "(PoC withheld)")[:_POC_BLOCK_CHARS]
        return await self._request_structured(
            ctx,
            RemediationPlan,
            self.prompt_name,
            finding_block=_build_finding_block(finding),
            poc_block=poc_text,
            source_block=_build_source_block(source_file),
            finding_ref=str(expected_ref),
        )


class RemediationRunResult(BaseModel):
    """Outcome of one remediation session over a scanned target."""

    report: RemediationReport = Field(description="Per-finding remediation records.")
    scan: ScanRunResult = Field(description="The underlying scan result and diagnostics.")


class RemediationService:
    """Coordinates scan reuse, patch proposal, isolated application, and re-exploitation."""

    def __init__(
        self,
        settings: MugiwaraSettings,
        max_findings: int = _DEFAULT_MAX_FINDINGS,
    ) -> None:
        """Store active settings and the per-run remediation cap.

        Args:
            settings: Validated application settings.
            max_findings: Maximum number of verified findings remediated per run.
        """
        self._settings = settings
        self._max_findings = max_findings

    async def run(
        self,
        target_override: str | None = None,
    ) -> RemediationRunResult:
        """Run the full pipeline: scan, then remediate every verified finding.

        Args:
            target_override: Optional target path overriding settings.

        Returns:
            The remediation report bundled with the underlying scan result.

        Raises:
            TargetPathError: If the target does not exist or is not a directory.
            ProviderNotSupportedError: If the configured provider is unavailable.
        """
        scan_result = await ScanOrchestrator(self._settings).run(target_override)
        return await self._remediate_scan(scan_result, Path(scan_result.report.target_path))

    async def run_stored_report(
        self,
        stored: StoredScanReport,
        *,
        project_root: str | Path,
    ) -> RemediationRunResult:
        """Remediate verified findings from a previously persisted report.

        No scanner is invoked: findings and evidence are consumed exactly as
        stored in the validated envelope. The project root is explicit and
        must be the very directory the report was produced for; this keeps
        stored findings from steering patches into an unintended tree.

        Args:
            stored: Envelope loaded through the secure report store.
            project_root: Explicit local project root to stage and patch.

        Returns:
            The remediation report bundled with the stored scan result.

        Raises:
            TargetPathError: If the project root is missing or not a directory.
            ReportTargetMismatchError: If the root differs from the scanned one.
        """
        root = Path(project_root).expanduser().resolve()
        if not root.is_dir():
            msg = f"Project root '{root}' does not exist or is not a directory."
            raise TargetPathError(msg)

        recorded = Path(stored.target.path).expanduser().resolve()
        if os.path.normcase(str(recorded)) != os.path.normcase(str(root)):
            msg = (
                f"Stored report {stored.report_id} was produced for '{recorded}', "
                f"which is not the requested project root '{root}'. Reports are "
                "bound to the exact directory they scanned; re-run 'mugiwara "
                "scan' at the new location if the project moved."
            )
            raise ReportTargetMismatchError(msg)

        scan_result = ScanRunResult(
            report=stored.scan,
            diagnostics=AgentDiagnostics(),
            phases_completed=[],
        )
        return await self._remediate_scan(scan_result, root)

    async def _remediate_scan(
        self,
        scan_result: ScanRunResult,
        root: Path,
    ) -> RemediationRunResult:
        """Shared remediation core over an already-produced scan result."""
        collector = WorkspaceCollector(self._settings.agents)
        sources: CollectedSources = collector.collect(root)

        provider = get_provider(self._settings.llm)
        ctx = AgentContext(
            provider=provider,
            settings=self._settings,
            sources=sources,
            target_root=str(root),
        )

        verified = [
            finding
            for finding in scan_result.report.findings
            if finding.status is FindingStatus.VERIFIED and finding.evidence is not None
        ]

        notes: list[str] = []

        if not verified:
            notes.append("No dynamically verified findings to remediate.")
            return RemediationRunResult(
                report=RemediationReport(
                    target_path=str(root),
                    notes=notes,
                ),
                scan=scan_result,
            )

        selected = verified[: self._max_findings]

        if len(selected) < len(verified):
            notes.append(
                f"Remediation capped at {len(selected)} of {len(verified)} verified findings."
            )

        entry_rel_path = _detect_entry_file(ctx)
        port = _detect_port(ctx)

        records = [
            await self._remediate_one(
                ctx,
                finding,
                expected_ref,
                entry_rel_path,
                port,
            )
            for expected_ref, finding in enumerate(selected)
        ]

        return RemediationRunResult(
            report=RemediationReport(
                target_path=str(root),
                records=records,
                notes=notes,
            ),
            scan=scan_result,
        )

    # ------------------------------------------------------------------
    # Per-finding pipeline
    # ------------------------------------------------------------------

    async def _remediate_one(
        self,
        ctx: AgentContext,
        finding: Finding,
        expected_ref: int,
        entry_rel_path: str | None,
        port: int,
    ) -> RemediationRecord:
        """Propose, apply (isolated copy only), and sea-trial one finding."""
        assert finding.evidence is not None

        evidence = finding.evidence

        record = RemediationRecord(
            finding_id=str(finding.id),
            title=finding.title,
            category=finding.category.value,
            severity=finding.severity.value,
            cwe_id=finding.cwe_id,
            location=_location_text(finding),
        )

        if finding.location is None:
            return self._fail(
                record,
                "finding has no source location; refusing to guess a target.",
            )

        vulnerable_file = ctx.source_index.get(finding.location.file_path)

        if vulnerable_file is None:
            return self._fail(
                record,
                f"target file '{finding.location.file_path}' was not among collected sources.",
            )

        if evidence.poc_script is None:
            return self._fail(
                record,
                "verification evidence lacks the original PoC script.",
            )

        if evidence.canary_token is None:
            return self._fail(
                record,
                "verification evidence lacks the canary token.",
            )

        try:
            plan = await RemediationAgent().propose_plan(
                ctx,
                finding,
                expected_ref,
                vulnerable_file,
                evidence,
            )
        except MugiwaraError as exc:
            return self._fail(
                record,
                f"plan generation failed: {exc}",
            )

        record.explanation = plan.explanation

        # --------------------------------------------------------------
        # Validate the proposed destination before touching staging.
        # --------------------------------------------------------------

        if plan.file_path not in ctx.source_paths:
            return self._fail(
                record,
                f"proposed patch targets '{plan.file_path}', which is not "
                "a collected source file; patch rejected.",
            )

        target_rel = plan.file_path
        original_content = _newline_normalized(ctx.source_index[target_rel].content)

        # --------------------------------------------------------------
        # Validate syntax before applying anything.
        # --------------------------------------------------------------

        syntax_error = validate_python_source(
            plan.patched_content,
            target_rel,
        )

        if syntax_error is not None:
            return self._fail(record, syntax_error)

        # --------------------------------------------------------------
        # Reject true no-op patches.
        #
        # Both sides are newline-normalized, so converting CRLF to LF
        # alone never counts as a remediation.
        # --------------------------------------------------------------

        if _newline_normalized(plan.patched_content) == _newline_normalized(original_content):
            return self._fail(
                record,
                "proposed patch is identical to the original file.",
            )

        # Record the canonical (LF) representation of the original source.
        record.file_path = target_rel
        record.original_content = original_content
        record.patched_content = plan.patched_content
        record.original_poc_sha256 = sha256_text(evidence.poc_script)
        record.unified_diff = build_unified_diff(
            original_content,
            plan.patched_content,
            target_rel,
        )

        # --------------------------------------------------------------
        # Apply only inside the disposable staging workspace.
        # --------------------------------------------------------------

        try:
            with StagingWorkspace(ctx.sources) as staging:
                staging.write_probe(
                    "readiness.py",
                    _READINESS_SCRIPT,
                )

                staging.write_probe(
                    _POSTFIX_PROBE_NAME,
                    evidence.poc_script,
                )

                staging.write_source(
                    target_rel,
                    plan.patched_content,
                )

                record.status = RemediationStatus.APPLIED

                if entry_rel_path is None:
                    return self._fail(
                        record,
                        "patch applied to the isolated copy, but no "
                        "runnable entrypoint was detected; the fix could "
                        "not be validated.",
                    )

                sandbox = get_sandbox(self._settings.sandbox)

                record.sandbox_backend = sandbox.backend_name
                record.sandbox_session_id = sandbox.session_id

                mount = WorkspaceMount(
                    host_path=staging.root,
                    read_only=False,
                )

                try:
                    await sandbox.start(mount)
                except (MugiwaraError, OSError) as exc:
                    return self._fail(
                        record,
                        f"sandbox could not start: {exc}",
                    )

                try:
                    exec_result = await self._run_sea_trial(
                        sandbox,
                        entry_rel_path,
                        port,
                        evidence,
                    )
                except (MugiwaraError, OSError) as exc:
                    return self._fail(
                        record,
                        f"sandbox execution failed during sea trial: {exc}",
                    )
                finally:
                    await sandbox.stop()

        except OSError as exc:
            return self._fail(
                record,
                f"staging workspace could not be materialized: {exc}",
            )

        return self._finalize_after_trial(
            record,
            exec_result,
            evidence,
        )

    async def _run_sea_trial(
        self,
        sandbox: BaseSandbox,
        entry_rel_path: str,
        port: int,
        evidence: Evidence,
    ) -> ExecResult:
        """Re-execute the original PoC against the patched target, verbatim."""
        assert evidence.poc_script is not None
        assert evidence.canary_token is not None

        config = self._settings.verification

        harness = _build_harness(
            entry_rel_path,
            f"{_CONTAINER_PROBE_DIR}/{_POSTFIX_PROBE_NAME}",
            port,
            config.readiness_wait_seconds,
        )

        environment = {
            TARGET_URL_ENV_VAR: f"http://127.0.0.1:{port}",
            CANARY_ENV_VAR: evidence.canary_token,
        }

        timeout = (
            config.poc_timeout_seconds
            + float(config.readiness_wait_seconds)
            + _TIMEOUT_SLACK_SECONDS
        )

        return await sandbox.exec_command(
            ["sh", "-c", harness],
            timeout_seconds=timeout,
            environment=environment,
            workdir="/workspace",
        )

    def _finalize_after_trial(
        self,
        record: RemediationRecord,
        exec_result: ExecResult,
        evidence: Evidence,
    ) -> RemediationRecord:
        """Map the post-patch execution onto the deterministic truth table."""
        assert evidence.canary_token is not None

        output = _HarnessOutput(exec_result.stdout)

        http_trace = _extract_http_trace(output.poc_log)

        # Observation requires the payload to reach an attacker-readable
        # channel; see _attacker_visible_output for why server logs and
        # the probe's own SENT/CLAIM transcript lines never qualify.
        canary_observed = evidence.canary_token in _attacker_visible_output(
            output.poc_log, http_trace
        )

        post_evidence = Evidence(
            poc_script=evidence.poc_script,
            reproduction_steps=evidence.reproduction_steps,
            http_trace=http_trace,
            stdout_log=output.target_log[:_LOG_SNIPPET_CHARS] or None,
            stderr_log=output.poc_log[:_LOG_SNIPPET_CHARS] or None,
            canary_found=canary_observed,
            canary_token=evidence.canary_token,
            verified_at=_utcnow(),
            sandbox_runtime_seconds=round(
                exec_result.duration_seconds,
                3,
            ),
        )

        record.post_validation_evidence = post_evidence
        record.validated_at = _utcnow()

        status, reason = _classify_post_fix_run(
            exec_result,
            output,
            canary_observed=canary_observed,
        )

        record.reason = reason
        record.status = status

        return record

    def _fail(
        self,
        record: RemediationRecord,
        reason: str,
    ) -> RemediationRecord:
        """Transition a record to FAILED with an honest explanation."""
        record.reason = reason
        record.status = RemediationStatus.FAILED
        return record


def _classify_post_fix_run(
    exec_result: ExecResult,
    output: _HarnessOutput,
    *,
    canary_observed: bool,
) -> tuple[RemediationStatus, str]:
    """Deterministic truth table for the post-patch exploit rerun."""

    if exec_result.timed_out or exec_result.exit_code is None:
        return (
            RemediationStatus.FAILED,
            "sea trial timed out before completing.",
        )

    if output.exit_code is None:
        return (
            RemediationStatus.FAILED,
            "harness produced no exit marker.",
        )

    if not output.ready_ok:
        return (
            RemediationStatus.FAILED,
            _readiness_failure_reason(output.target_log) + " The patch was applied to the isolated "
            "copy only; the original target is untouched.",
        )

    verdict = _extract_verdict(output.poc_log)

    if verdict is None:
        return (
            RemediationStatus.FAILED,
            "post-patch rerun produced no parsable MUGIWARA_VERDICT line.",
        )

    claimed = bool(verdict.get("canary_found", False))

    if claimed and canary_observed:
        return (
            RemediationStatus.NOT_FIXED,
            "original exploit still reproduces: the canary token "
            "was observed after applying the patch.",
        )

    if claimed:
        return (
            RemediationStatus.FAILED,
            "inconclusive: rerun claimed exploitation but the canary token was never observed.",
        )

    if exec_result.exit_code == 0:
        return (
            RemediationStatus.VERIFIED_FIXED,
            "original exploit no longer reproduces against the patched target.",
        )

    return (
        RemediationStatus.FAILED,
        "rerun exited nonzero while claiming a clean result.",
    )


def build_remediation_bundle(
    result: RemediationRunResult,
    *,
    tool_version: str,
) -> dict[str, Any]:
    """Serialize a run into the JSON bundle consumed by the local dashboard."""
    scan = result.scan
    counts = result.report.status_counts()

    counts["verified_findings_total"] = sum(
        1 for finding in scan.report.findings if finding.status is FindingStatus.VERIFIED
    )

    return {
        "schema": "mugiwara.fix-bundle",
        "version": 1,
        "tool_version": tool_version,
        "generated_at": _utcnow().isoformat(),
        "target_path": result.report.target_path,
        "scan_profile": scan.report.scan_profile,
        "pipeline_phases": [phase.value for phase in scan.phases_completed],
        "diagnostics": scan.diagnostics.model_dump(mode="json"),
        "summary": counts,
        "findings": [finding.model_dump(mode="json") for finding in scan.report.findings],
        "remediations": [record.model_dump(mode="json") for record in result.report.records],
        "notes": result.report.notes,
    }


async def run_remediation_async(
    settings: MugiwaraSettings,
    target_override: str | None = None,
    max_findings: int = _DEFAULT_MAX_FINDINGS,
) -> RemediationRunResult:
    """Asynchronously run scan + remediation for one target."""
    return await RemediationService(
        settings,
        max_findings=max_findings,
    ).run(target_override)


def run_remediation(
    settings: MugiwaraSettings,
    target_override: str | None = None,
    max_findings: int = _DEFAULT_MAX_FINDINGS,
) -> RemediationRunResult:
    """Synchronously run scan + remediation for one target."""
    return asyncio.run(
        run_remediation_async(
            settings,
            target_override,
            max_findings,
        )
    )


__all__ = [
    "RemediationAgent",
    "RemediationRunResult",
    "RemediationService",
    "build_remediation_bundle",
    "run_remediation",
    "run_remediation_async",
]
