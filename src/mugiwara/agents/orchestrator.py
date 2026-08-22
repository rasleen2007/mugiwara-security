"""Scan orchestration: phase sequencing, budget governance, and fault tolerance."""

import asyncio
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field

from mugiwara.agents.base import AgentContext
from mugiwara.agents.discovery import DiscoveryAgent
from mugiwara.agents.models import AgentDiagnostics
from mugiwara.agents.recon import ReconAgent
from mugiwara.agents.sources import CollectedSources, WorkspaceCollector
from mugiwara.agents.staging import StagingWorkspace
from mugiwara.agents.verification import VerificationAgent
from mugiwara.core.config import MugiwaraSettings, SandboxMode, ScanProfile
from mugiwara.core.exceptions import MugiwaraError
from mugiwara.models.finding import Finding
from mugiwara.models.report import ScanReport
from mugiwara.providers.factory import get_provider
from mugiwara.sandbox.base import WorkspaceMount
from mugiwara.sandbox.factory import get_sandbox


class SessionPhase(str, Enum):
    """Lifecycle phases of one orchestrated scan session."""

    VALIDATING = "validating"
    RECON = "recon"
    DISCOVERY = "discovery"
    VERIFICATION = "verification"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanRunResult(BaseModel):
    """Outcome of a full scan run: the report plus operational diagnostics."""

    report: ScanReport = Field(description="The generated scan report.")
    diagnostics: AgentDiagnostics = Field(description="Session operational diagnostics.")
    phases_completed: list[SessionPhase] = Field(
        default_factory=list,
        description="Phases that finished successfully, in order.",
    )


class ScanOrchestrator:
    """Coordinates the recon, discovery, and verification agents for a single target.

    The orchestrator owns no LLM or filesystem logic itself; it validates the
    target via :class:`WorkspaceCollector`, delegates to agents through
    :class:`AgentContext`, and guarantees a well-formed :class:`ScanReport`
    even when individual phases degrade to heuristic-only operation. Dynamic
    verification runs against a disposable staging copy inside an ephemeral
    sandbox; the original target is never mounted or mutated.
    """

    def __init__(self, settings: MugiwaraSettings) -> None:
        """Store the active settings.

        Args:
            settings: Validated application settings.
        """
        self._settings = settings
        self.phase: SessionPhase = SessionPhase.VALIDATING
        self.diagnostics = AgentDiagnostics()

    async def run(self, target_override: str | None = None) -> ScanRunResult:
        """Execute the full static analysis pipeline.

        Args:
            target_override: Optional CLI target path overriding settings.

        Returns:
            The scan report with session diagnostics.

        Raises:
            TargetPathError: If the target path does not exist or is not a
                directory. This is unrecoverable and aborts before any agent
                runs.
        """
        self.phase = SessionPhase.VALIDATING
        raw_target = Path(target_override or self._settings.scan.target_path)
        collector = WorkspaceCollector(self._settings.agents)
        sources: CollectedSources = collector.collect(raw_target)
        root = raw_target.resolve()

        provider = get_provider(self._settings.llm)
        ctx = AgentContext(
            provider=provider,
            settings=self._settings,
            sources=sources,
            target_root=str(root),
        )
        self.diagnostics = ctx.diagnostics

        findings: list[Finding] = []
        phases_completed: list[SessionPhase] = []

        self.phase = SessionPhase.RECON
        try:
            surface = await ReconAgent().run(ctx)
            ctx.attack_surface = surface
            phases_completed.append(SessionPhase.RECON)
        except MugiwaraError as exc:
            ctx.diagnostics.degraded = True
            ctx.diagnostics.errors.append(f"[orchestrator] recon phase failed: {exc}")

        self.phase = SessionPhase.DISCOVERY
        try:
            findings = await DiscoveryAgent().run(ctx)
            phases_completed.append(SessionPhase.DISCOVERY)
        except MugiwaraError as exc:
            ctx.diagnostics.degraded = True
            ctx.diagnostics.errors.append(f"[orchestrator] discovery phase failed: {exc}")

        ctx.findings = findings

        verification_active = (
            self._settings.verification.enabled
            and self._settings.scan.profile is not ScanProfile.FAST
            and self._settings.sandbox.mode is not SandboxMode.NONE
        )
        if verification_active:
            self.phase = SessionPhase.VERIFICATION
            try:
                with StagingWorkspace(sources) as staging:
                    mount = WorkspaceMount(host_path=staging.root, read_only=False)
                    sandbox = get_sandbox(self._settings.sandbox)
                    try:
                        await sandbox.start(mount)
                        ctx.sandbox = sandbox
                        ctx.staging = staging
                        await VerificationAgent().run(ctx)
                    finally:
                        ctx.sandbox = None
                        ctx.staging = None
                        await sandbox.stop()
                phases_completed.append(SessionPhase.VERIFICATION)
            except (MugiwaraError, OSError) as exc:
                ctx.diagnostics.degraded = True
                ctx.diagnostics.errors.append(f"[orchestrator] verification phase failed: {exc}")

        ctx.diagnostics.tokens_used = ctx.budget.used_tokens
        self.diagnostics = ctx.diagnostics

        report = ScanReport(
            target_path=str(root),
            scan_profile=self._settings.scan.profile.value,
            findings=findings,
        )
        report.calculate_summary()
        self.phase = SessionPhase.COMPLETED
        return ScanRunResult(
            report=report,
            diagnostics=ctx.diagnostics,
            phases_completed=phases_completed,
        )


async def run_scan_async(
    settings: MugiwaraSettings,
    target_override: str | None = None,
) -> ScanRunResult:
    """Asynchronously run a complete scan session.

    Args:
        settings: Active application settings (LLM config selects provider).
        target_override: Optional target path overriding ``settings.scan.target_path``.

    Returns:
        Report and diagnostics for the completed session.

    Raises:
        ProviderNotSupportedError: If a non-mock provider is requested before
            its implementation phase.
        TargetPathError: If the scan target is missing or not a directory.
    """
    orchestrator = ScanOrchestrator(settings)
    return await orchestrator.run(target_override)


def run_scan(
    settings: MugiwaraSettings,
    target_override: str | None = None,
) -> ScanRunResult:
    """Synchronously run a complete scan session.

    Args:
        settings: Active application settings.
        target_override: Optional target path overriding settings.

    Returns:
        Report and diagnostics for the completed session.
    """
    return asyncio.run(run_scan_async(settings, target_override))


__all__ = [
    "ScanOrchestrator",
    "ScanRunResult",
    "SessionPhase",
    "run_scan",
    "run_scan_async",
]
