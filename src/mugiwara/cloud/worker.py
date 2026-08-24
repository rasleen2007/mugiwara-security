"""Isolated asynchronous scan worker (Phase 3).

Consumes owner-scoped queued scan jobs from the Supabase Postgres queue using
``FOR UPDATE SKIP LOCKED``, downloads the user's private source archive,
executes the UNCHANGED Mugiwara pipeline (hardened intake + orchestrator +
report store), and persists the resulting envelope as an owner-attributed
report row.

Security contracts carried over from Phase 2 and enforced here:
- A job is processed only when its storage key matches the canonical
  ``<owner_uid>/<job_uuid>/source.zip`` layout AND the owner prefix equals the
  job's own ``owner_id``. Anything else permanently fails the job without a
  single storage byte being fetched.
- The report row is always inserted with ``owner_id`` copied from the JOB row
  (never derived from envelope contents), so users can only ever see results
  for their own submissions.
- Worker-internal filesystem locations are scrubbed from stored documents;
  finding paths stay relative to the uploaded archive namespace.
- Failure messages surfaced into the database are sanitized: typed intake
  rejections pass through their static text, everything else degrades to the
  exception class name. Source contents, PoCs, secrets, and scratch paths are
  never recorded.
- Crashes are recovered by lease expiry: expired running jobs return to the
  queue with attempts preserved, bounded by ``worker_max_attempts``.

The worker runs no background threads of its own; one process handles one job
at a time. Horizontal scale-out is safe because claiming is atomic in SQL.
"""

import hashlib
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast

from mugiwara.cloud.config import CloudSettings
from mugiwara.cloud.db import ScanJobRow
from mugiwara.cloud.storage import ObjectTooLargeError, StorageError, SupabaseStorage
from mugiwara.core.config import MugiwaraSettings, ScanProfile
from mugiwara.core.exceptions import ArchiveRejectedError, TargetNotAvailableError
from mugiwara.intake import open_zip_target
from mugiwara.ui.scan_runner import (
    PhaseObserver,
    PipelineScanOutcome,
    execute_pipeline_scan,
)

PhaseRecorder = Callable[[list[str]], None]


class ScanExecutor(Protocol):
    """The engine entry point the worker drives (mirrors scan_runner)."""

    def __call__(
        self,
        settings: MugiwaraSettings,
        target: str,
        *,
        on_phase: PhaseObserver | None = None,
    ) -> PipelineScanOutcome: ...


_MAX_PHASE_ENTRIES = 60


class WorkerDatabase(Protocol):
    """Queue-side persistence surface used by the worker."""

    def claim_next_scan_job(
        self, *, worker_id: str, lease_seconds: int, max_attempts: int
    ) -> ScanJobRow | None: ...

    def update_job_phases(self, job_id: str, phases: list[str]) -> bool: ...

    def complete_job(self, job_id: str) -> bool: ...

    def fail_job(self, job_id: str, error: str, *, retry: bool) -> str | None: ...

    def recover_expired_leases(self, *, max_attempts: int) -> list[str]: ...

    def insert_report_for_job(
        self,
        *,
        owner_id: str,
        project_id: str | None,
        job_id: str,
        origin: str,
        target_label: str,
        configuration: dict[str, object],
        summary: dict[str, object],
        envelope: dict[str, object],
    ) -> bool: ...


@dataclass(frozen=True)
class WorkerOutcome:
    """Result of processing exactly one claimed job."""

    job_id: str
    status: str
    report_id: str | None = None


def _sanitize_error(exc: Exception) -> str:
    if isinstance(exc, (ArchiveRejectedError, TargetNotAvailableError)):
        return f"source archive rejected by hardened intake: {exc}"
    return f"scan failed ({type(exc).__name__})"


def _validate_source_key(job: ScanJobRow) -> bool:
    from mugiwara.cloud.storage import UPLOAD_PATH_PATTERN

    match = UPLOAD_PATH_PATTERN.match(job.source_key)
    return (
        match is not None
        and match.group("owner") == job.owner_id
        and match.group("job") == job.id
        and job.source_bucket == "scan-uploads"
    )


def _sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _engine_settings_for(
    engine: MugiwaraSettings, job: ScanJobRow, reports_root: Path
) -> MugiwaraSettings:
    """Per-job engine settings: requested profile + isolated report root."""
    settings = engine.model_copy(deep=True)
    settings.scan.profile = ScanProfile(job.scan_profile)
    settings.output.reports_dir = str(reports_root)
    return settings


def _sanitize_envelope(envelope: dict[str, object], job: ScanJobRow) -> dict[str, object]:
    """Replace worker-local paths with the stable upload namespace."""
    neutral = f"uploads/{job.source_key}"
    document = dict(envelope)
    scan_block = document.get("scan")
    target_block = document.get("target")
    if isinstance(scan_block, dict):
        scan_block = dict(scan_block)
        scan_block["target_path"] = neutral
        document["scan"] = scan_block
    if isinstance(target_block, dict):
        target_block = dict(target_block)
        target_block["path"] = neutral
        document["target"] = target_block
    return document


def process_job(
    job: ScanJobRow,
    *,
    db: WorkerDatabase,
    storage: SupabaseStorage,
    cloud: CloudSettings,
    engine_settings: MugiwaraSettings,
    executor: ScanExecutor = execute_pipeline_scan,
    workdir: Path | None = None,
) -> WorkerOutcome:
    """Run one claimed job end-to-end; never raises for job-level failures."""
    if not _validate_source_key(job):
        db.fail_job(job.id, "source reference failed validation", retry=False)
        return WorkerOutcome(job_id=job.id, status="failed")

    base_tmp = Path(tempfile.gettempdir()) if workdir is None else Path(workdir)
    base_tmp.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix=f"mugiwara-job-{job.id}-", dir=base_tmp))
    archive_path = scratch / "source.zip"
    try:
        try:
            storage.download_to_file(
                job.source_bucket,
                job.source_key,
                archive_path,
                cloud.max_download_bytes,
            )
        except ObjectTooLargeError as exc:
            db.fail_job(job.id, exc.detail, retry=False)
            return WorkerOutcome(job_id=job.id, status="failed")
        except StorageError as exc:
            db.fail_job(job.id, exc.detail, retry=True)
            return WorkerOutcome(job_id=job.id, status="retrying")

        if job.source_sha256 is not None and _sha256_of(archive_path) != job.source_sha256:
            db.fail_job(
                job.id,
                "uploaded archive hash does not match the declared checksum",
                retry=False,
            )
            return WorkerOutcome(job_id=job.id, status="failed")

        phases: list[str] = []

        def record_phase(phase: object, detail: str) -> None:
            entry = f"{getattr(phase, 'value', phase)}: {detail}"
            phases.append(entry)
            db.update_job_phases(job.id, phases[-_MAX_PHASE_ENTRIES:])

        try:
            outcome = executor(
                _engine_settings_for(engine_settings, job, scratch / "reports"),
                str(archive_path),
                on_phase=record_phase,
            )
        except Exception as exc:
            db.fail_job(job.id, _sanitize_error(exc), retry=True)
            return WorkerOutcome(job_id=job.id, status="retrying")

        if outcome.envelope is None or outcome.persistence_error is not None:
            detail = outcome.persistence_error or "engine produced no durable report"
            db.fail_job(job.id, f"result handling failed: {detail}", retry=False)
            return WorkerOutcome(job_id=job.id, status="failed")

        envelope = _sanitize_envelope(
            dict(outcome.envelope.model_dump(mode="json", by_alias=True)), job
        )
        scan_block = cast(dict[str, Any], envelope["scan"])
        inserted = db.insert_report_for_job(
            owner_id=job.owner_id,
            project_id=job.project_id,
            job_id=job.id,
            origin="archive",
            target_label="source.zip",
            configuration=cast(dict[str, object], envelope["configuration"]),
            summary=cast(dict[str, object], scan_block["summary"]),
            envelope=envelope,
        )
        # A conflicting insert means a previous attempt crashed after persisting
        # the report but before completing the job; completing now is recovery.
        if db.complete_job(job.id):
            return WorkerOutcome(
                job_id=job.id,
                status="completed",
                report_id=str(envelope["report_id"]) if inserted else None,
            )
        db.fail_job(job.id, "job left running state before completion", retry=False)
        return WorkerOutcome(job_id=job.id, status="failed")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def run_recovery(db: WorkerDatabase, *, max_attempts: int) -> list[str]:
    """Return crashed (lease-expired) jobs to the queue, fail exhausted ones."""
    return db.recover_expired_leases(max_attempts=max_attempts)


def run_worker_once(
    *,
    db: WorkerDatabase,
    storage: SupabaseStorage,
    cloud: CloudSettings,
    engine_settings: MugiwaraSettings,
    executor: ScanExecutor = execute_pipeline_scan,
    worker_id: str = "worker",
    workdir: Path | None = None,
) -> WorkerOutcome | None:
    """Claim and process at most one job; returns None when queue empty."""
    run_recovery(db, max_attempts=cloud.worker_max_attempts)
    job = db.claim_next_scan_job(
        worker_id=worker_id,
        lease_seconds=cloud.worker_lease_seconds,
        max_attempts=cloud.worker_max_attempts,
    )
    if job is None:
        return None
    return process_job(
        job,
        db=db,
        storage=storage,
        cloud=cloud,
        engine_settings=engine_settings,
        executor=executor,
        workdir=workdir,
    )


def run_worker_loop(
    *,
    db: WorkerDatabase,
    storage: SupabaseStorage,
    cloud: CloudSettings,
    engine_settings: MugiwaraSettings,
    executor: ScanExecutor = execute_pipeline_scan,
    worker_id: str = "worker",
    should_stop: Callable[[], bool] = lambda: False,
    workdir: Path | None = None,
) -> int:
    """Synchronous polling loop; returns number of jobs processed."""
    processed = 0
    import time

    while not should_stop():
        outcome = run_worker_once(
            db=db,
            storage=storage,
            cloud=cloud,
            engine_settings=engine_settings,
            executor=executor,
            worker_id=worker_id,
            workdir=workdir,
        )
        if outcome is not None:
            processed += 1
            continue
        time.sleep(cloud.worker_poll_interval_seconds)
    return processed


def main() -> None:
    """Entry point for ``mugiwara-cloud-worker``; loopback-safe defaults."""
    from mugiwara.cloud.config import CloudConfigError, load_settings

    try:
        cloud = load_settings()
    except CloudConfigError as exc:
        import sys

        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from exc

    from mugiwara.cloud.db import PostgresDatabase

    database = PostgresDatabase(cloud.database_url.get_secret_value())
    storage = SupabaseStorage(
        base_url=cloud.supabase_url,
        service_key=cloud.supabase_service_role_key,
        upload_bucket=cloud.upload_bucket,
        export_bucket=cloud.export_bucket,
        timeout_seconds=cloud.http_timeout_seconds,
    )
    engine = MugiwaraSettings()
    count = run_worker_loop(
        db=database,
        storage=storage,
        cloud=cloud,
        engine_settings=engine,
        should_stop=lambda: False,
    )
    print(f"processed {count} jobs")


# Re-exported so deployments can pre-flight archives identically to the CLI.
__all__ = [
    "WorkerOutcome",
    "open_zip_target",
    "process_job",
    "run_recovery",
    "run_worker_loop",
    "run_worker_once",
]
