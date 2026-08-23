"""Typed glue between the workbench UI server and the existing Mugiwara engine.

This module contains NO scanning logic of its own. It wires the exact same
engine primitives the ``mugiwara scan`` CLI uses — hardened ZIP intake, the
scan orchestrator, and the durable report store — into calls that raise typed
exceptions suitable for a JSON API instead of CLI exits.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from mugiwara.agents.orchestrator import ScanRunResult, SessionPhase, run_scan
from mugiwara.core.config import MugiwaraSettings
from mugiwara.core.exceptions import (
    ArchiveRejectedError,
    MugiwaraError,
    TargetNotAvailableError,
)
from mugiwara.intake import open_zip_target
from mugiwara.models.report import ScanReport
from mugiwara.reports.store import (
    ReportStore,
    StoredScanReport,
    TargetMetadata,
    resolve_report_root,
    snapshot_from_settings,
)

PhaseObserver = Callable[[SessionPhase, str], None]


@dataclass
class PipelineScanOutcome:
    """Result of one engine scan plus its persistence outcome."""

    report: ScanReport
    envelope: StoredScanReport | None = None
    persistence_error: str | None = None
    phase_details: list[tuple[str, str]] = field(default_factory=list)


def execute_pipeline_scan(
    settings: MugiwaraSettings,
    target: str,
    *,
    on_phase: PhaseObserver | None = None,
) -> PipelineScanOutcome:
    """Run one authorized scan through the existing engine and persist it.

    Directory targets go straight to the orchestrator; ``.zip`` targets are
    screened and extracted by the hardened intake layer into a disposable
    tree that is always removed afterwards, exactly like the CLI flow.

    Args:
        settings: Effective settings for this run.
        target: Local project directory or ZIP archive path.
        on_phase: Optional observer receiving secret-free phase events.

    Returns:
        The scan outcome including the persisted envelope when saving worked.

    Raises:
        MugiwaraError: On target rejection or any typed engine failure.
        OSError: On filesystem failures during intake or scanning.
    """
    details: list[tuple[str, str]] = []

    def observe(phase: SessionPhase, detail: str) -> None:
        """Record one phase event and forward it to the caller's observer."""
        details.append((phase.value, detail))
        if on_phase is not None:
            on_phase(phase, detail)

    if Path(target).suffix.lower() == ".zip":
        result = _execute_zip_scan(settings, target, observe)
        is_archive = True
    else:
        result = run_scan(settings, target_override=target, on_phase=observe)
        is_archive = False

    envelope, persistence_error = _persist(settings, result, is_archive=is_archive)
    return PipelineScanOutcome(
        report=result.report,
        envelope=envelope,
        persistence_error=persistence_error,
        phase_details=details,
    )


def _execute_zip_scan(
    settings: MugiwaraSettings,
    target: str,
    observe: PhaseObserver,
) -> ScanRunResult:
    """Scan an archive through the hardened ZIP intake, then clean up."""
    archive_source = Path(target).expanduser().resolve()
    try:
        zip_intake = open_zip_target(target)
    except (TargetNotAvailableError, ArchiveRejectedError):
        raise
    with zip_intake as intake_target:
        result = run_scan(
            settings,
            target_override=str(intake_target.target_path),
            on_phase=observe,
        )
    # The disposable extraction tree no longer exists, so the report binds to
    # the durable archive location; finding paths stay relative and valid.
    result.report.target_path = str(archive_source)
    return result


def _persist(
    settings: MugiwaraSettings,
    result: ScanRunResult,
    *,
    is_archive: bool,
) -> tuple[StoredScanReport | None, str | None]:
    """Archive the completed scan using the shared report store rules.

    Mirrors the CLI persistence contract: directory scans anchor the store at
    the scanned project, archive scans fall back to the configured root, and
    a persistence failure never invalidates the scan itself.
    """
    anchor = None if is_archive else result.report.target_path
    origin = "archive" if is_archive else "directory"
    try:
        store = ReportStore(resolve_report_root(settings, anchor))
        envelope = store.save(
            result.report,
            target=TargetMetadata(
                path=result.report.target_path,
                origin=origin,
                files_collected=result.diagnostics.files_collected,
                secret_markers_found=result.diagnostics.secret_markers_found,
            ),
            configuration=snapshot_from_settings(settings),
        )
    except (MugiwaraError, OSError) as exc:
        return None, f"Scan succeeded, but the report could not be persisted: {exc}"
    return envelope, None
