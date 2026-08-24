"""Worker tests for the cloud scan pipeline (Phase 3).

Covers the mandated matrix: atomic claiming, owner isolation, storage-key
validation, successful execution, failure/retry semantics, lease-expiry crash
recovery, and state-transition guards - all against hermetic doubles - plus
one real engine integration run using the mock LLM provider and mock sandbox.
"""

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

from mugiwara.cloud.config import MAX_UPLOAD_BYTES, CloudSettings
from mugiwara.cloud.db import CLAIM_SCAN_JOB_SQL, RECOVER_EXPIRED_LEASES_SQL, ScanJobRow
from mugiwara.cloud.worker import (
    process_job,
    run_recovery,
    run_worker_loop,
    run_worker_once,
)
from mugiwara.core.config import (
    LLMConfig,
    LLMProviderType,
    MugiwaraSettings,
    SandboxConfig,
    SandboxMode,
)
from mugiwara.models.report import ScanReport
from mugiwara.providers.mock import MockLLMProvider
from mugiwara.reports.store import StoredScanReport, parse_stored_report
from mugiwara.ui.scan_runner import PipelineScanOutcome
from tests.unit.cloud_support import (
    USER_A,
    USER_B,
    InMemoryWorkerDatabase,
    RecordingStorage,
    build_envelope_document,
    default_settings,
)

FINDING_SOURCE = "api_key = 'supersecret9'\nprint(api_key)\n"


@pytest.fixture()
def db() -> InMemoryWorkerDatabase:
    return InMemoryWorkerDatabase()


@pytest.fixture()
def storage() -> RecordingStorage:
    return RecordingStorage()


@pytest.fixture()
def cloud() -> CloudSettings:
    settings = default_settings()
    object.__setattr__(settings, "worker_poll_interval_seconds", 0.0)  # frozen model
    return settings


@pytest.fixture()
def engine() -> MugiwaraSettings:
    return MugiwaraSettings(
        llm=LLMConfig(provider=LLMProviderType.MOCK),
        sandbox=SandboxConfig(mode=SandboxMode.MOCK),
    )


def _fake_envelope(target: str = "demo.zip") -> StoredScanReport:
    document = build_envelope_document()
    document["scan"]["target_path"] = target  # type: ignore[index]
    document["target"]["path"] = target  # type: ignore[index]
    return StoredScanReport.model_validate(document)


def _fake_executor(
    envelope: StoredScanReport | None = None,
    error: Exception | None = None,
) -> Any:
    """Deterministic stand-in for execute_pipeline_scan."""

    def execute(
        settings: MugiwaraSettings, target: str, on_phase: Any = None
    ) -> PipelineScanOutcome:
        if error is not None:
            raise error
        stored = envelope or _fake_envelope()
        report = ScanReport.model_validate(stored.model_dump(mode="json")["scan"])
        return PipelineScanOutcome(report=report, envelope=stored, persistence_error=None)

    return execute


def _seed_upload(storage: RecordingStorage, job: ScanJobRow, payload: bytes) -> str:
    storage.payloads[job.source_key] = payload
    return hashlib.sha256(payload).hexdigest()


# -- claim mechanics -----------------------------------------------------------


def test_claim_sql_is_atomic_and_scan_only() -> None:
    lowered = CLAIM_SCAN_JOB_SQL.lower()
    assert "for update skip locked" in lowered
    assert "kind = 'scan'" in lowered
    assert "attempts < %s" in lowered
    assert "status = 'queued'" in lowered
    recovery = RECOVER_EXPIRED_LEASES_SQL.lower()
    assert "worker_lease_until < now()" in recovery
    assert "attempts >= %s" in recovery
    assert "status = 'failed'" in recovery


def test_claims_are_exclusive_between_workers(db: InMemoryWorkerDatabase) -> None:
    first = db.add_job()
    second = db.add_job()
    claimed_a = db.claim_next_scan_job(worker_id="w1", lease_seconds=600, max_attempts=3)
    claimed_b = db.claim_next_scan_job(worker_id="w2", lease_seconds=600, max_attempts=3)
    ids = {claimed_a.id if claimed_a else None, claimed_b.id if claimed_b else None}
    assert ids == {first.id, second.id}
    assert db.claim_next_scan_job(worker_id="w1", lease_seconds=600, max_attempts=3) is None


def test_claim_increments_attempts_and_sets_lease(db: InMemoryWorkerDatabase) -> None:
    job = db.add_job()
    claimed = db.claim_next_scan_job(worker_id="w1", lease_seconds=600, max_attempts=3)
    assert claimed is not None and claimed.id == job.id
    assert claimed.attempts == 1
    assert claimed.status == "running"
    assert claimed.worker_lease_until is not None
    stored = db._find(job.id)
    assert stored is not None and stored.attempts == 1


def test_cancelled_completed_and_exhausted_jobs_never_claimed(
    db: InMemoryWorkerDatabase,
) -> None:
    db.add_job(status="cancelled")
    db.add_job(status="completed")
    db.add_job(attempts=3)
    db.add_job(kind="fix")
    assert db.claim_next_scan_job(worker_id="w", lease_seconds=60, max_attempts=3) is None


# -- owner isolation & storage-key validation ------------------------------------


def test_foreign_owner_prefix_fails_without_download(
    db: InMemoryWorkerDatabase,
    storage: RecordingStorage,
    cloud: CloudSettings,
    engine: MugiwaraSettings,
) -> None:
    job = db.add_job(
        owner_id=USER_A,
        source_key=f"{USER_B}/99999999-9999-4999-8999-999999999999/source.zip",
    )
    outcome = process_job(
        job,
        db=db,
        storage=storage,
        cloud=cloud,
        engine_settings=engine,
        executor=_fake_executor(),
    )
    assert outcome.status == "failed"
    assert storage.download_calls == []
    assert db.reports == {}
    assert db.errors[job.id] == "source reference failed validation"
    stored = db._find(job.id)
    assert stored is not None and stored.status == "failed"


def test_owner_and_job_segments_must_match_the_row(
    db: InMemoryWorkerDatabase,
    storage: RecordingStorage,
    cloud: CloudSettings,
    engine: MugiwaraSettings,
) -> None:
    mismatched_job_segment = f"{USER_A}/00000000-0000-4000-8000-000000000000/source.zip"
    traversal = "../escape/source.zip"
    wrong_bucket_kwargs: dict[str, Any] = {"source_bucket": "report-exports"}
    cases = [mismatched_job_segment, traversal]
    for key_or_bucket in cases:
        job = db.add_job(source_key=key_or_bucket)
        outcome = process_job(
            job,
            db=db,
            storage=storage,
            cloud=cloud,
            engine_settings=engine,
            executor=_fake_executor(),
        )
        assert outcome.status == "failed", key_or_bucket
    bucket_job = db.add_job(**wrong_bucket_kwargs)
    outcome = process_job(
        bucket_job,
        db=db,
        storage=storage,
        cloud=cloud,
        engine_settings=engine,
        executor=_fake_executor(),
    )
    assert outcome.status == "failed"
    assert storage.download_calls == []
    assert all(j.status == "failed" for j in db.jobs)


# -- successful execution ---------------------------------------------------------


def test_successful_run_inserts_owner_scoped_report_and_completes(
    db: InMemoryWorkerDatabase,
    storage: RecordingStorage,
    cloud: CloudSettings,
    engine: MugiwaraSettings,
    tmp_path: Path,
) -> None:
    created = db.add_job(owner_id=USER_B, scan_profile="fast")
    _seed_upload(storage, created, b"zip-bytes")
    claimed = db.claim_next_scan_job(worker_id="w", lease_seconds=600, max_attempts=3)
    assert claimed is not None

    outcome = process_job(
        claimed,
        db=db,
        storage=storage,
        cloud=cloud,
        engine_settings=engine,
        executor=_fake_executor(),
        workdir=tmp_path,
    )

    assert outcome.status == "completed"
    (owner, report_id), row = next(iter(db.reports.items()))
    assert owner == USER_B
    assert row.owner_id == USER_B
    assert row.report_id == outcome.report_id == report_id
    neutral = f"uploads/{created.source_key}"
    scan_block = row.envelope["scan"]
    target_block = row.envelope["target"]
    assert scan_block["target_path"] == neutral  # type: ignore[index]
    assert target_block["path"] == neutral  # type: ignore[index]
    assert str(tmp_path) not in json.dumps(row.envelope)
    assert db.phase_updates == []  # fake executor never emits phases
    stored = db._find(created.id)
    assert stored is not None and stored.status == "completed"


def test_phase_progress_is_persisted_during_execution(
    db: InMemoryWorkerDatabase,
    storage: RecordingStorage,
    cloud: CloudSettings,
    engine: MugiwaraSettings,
) -> None:
    def phased_executor(settings: Any, target: str, on_phase: Any = None) -> Any:
        class Phase:
            value = "collection"

        if on_phase is not None:
            on_phase(Phase(), "gathered files")
        return _fake_executor()(settings, target, on_phase)

    job = db.add_job()
    _seed_upload(storage, job, b"bytes")
    claimed = db.claim_next_scan_job(worker_id="w", lease_seconds=600, max_attempts=3)
    assert claimed is not None
    outcome = process_job(
        claimed,
        db=db,
        storage=storage,
        cloud=cloud,
        engine_settings=engine,
        executor=phased_executor,
    )
    assert outcome.status == "completed"
    assert any("collection: gathered files" in entry for entry in db.phase_updates[0][1])


def test_sha256_mismatch_fails_permanently_without_executing(
    db: InMemoryWorkerDatabase,
    storage: RecordingStorage,
    cloud: CloudSettings,
    engine: MugiwaraSettings,
) -> None:
    executed: list[Any] = []

    def spy_executor(*args: Any, **kwargs: Any) -> PipelineScanOutcome:
        executed.append(args)
        raise AssertionError("executor must not run")

    digest = hashlib.sha256(b"declared-bytes").hexdigest()
    good = db.add_job(source_sha256=digest)
    _seed_upload(storage, good, b"declared-bytes")
    good_claimed = db.claim_next_scan_job(worker_id="w", lease_seconds=600, max_attempts=3)
    assert good_claimed is not None
    good_outcome = process_job(
        good_claimed,
        db=db,
        storage=storage,
        cloud=cloud,
        engine_settings=engine,
        executor=_fake_executor(),
    )
    assert good_outcome.status == "completed"

    bad = db.add_job(source_sha256=digest)
    _seed_upload(storage, bad, b"tampered-bytes")
    bad_claimed = db.claim_next_scan_job(worker_id="w", lease_seconds=600, max_attempts=3)
    assert bad_claimed is not None
    bad_outcome = process_job(
        bad_claimed,
        db=db,
        storage=storage,
        cloud=cloud,
        engine_settings=engine,
        executor=spy_executor,
    )
    assert bad_outcome.status == "failed"
    assert executed == []
    assert db.errors[bad.id] == "uploaded archive hash does not match the declared checksum"


# -- download failures / retry semantics --------------------------------------------


def test_storage_outage_requeues_with_retry_semantics(
    db: InMemoryWorkerDatabase,
    storage: RecordingStorage,
    cloud: CloudSettings,
    engine: MugiwaraSettings,
) -> None:
    storage.outage = True
    job = db.add_job()
    claimed = db.claim_next_scan_job(worker_id="w", lease_seconds=600, max_attempts=3)
    assert claimed is not None and claimed.attempts == 1
    outcome = process_job(
        claimed,
        db=db,
        storage=storage,
        cloud=cloud,
        engine_settings=engine,
        executor=_fake_executor(),
    )
    assert outcome.status == "retrying"
    stored = db._find(job.id)
    assert stored is not None
    assert stored.status == "queued"
    assert stored.attempts == 1  # attempts persist across requeues
    assert db.errors[job.id] == "storage service unreachable"


def test_missing_object_requeues_for_late_uploaders(
    db: InMemoryWorkerDatabase,
    storage: RecordingStorage,
    cloud: CloudSettings,
    engine: MugiwaraSettings,
) -> None:
    job = db.add_job()  # no payload registered -> 404 semantics
    claimed = db.claim_next_scan_job(worker_id="w", lease_seconds=600, max_attempts=3)
    assert claimed is not None
    outcome = process_job(
        claimed,
        db=db,
        storage=storage,
        cloud=cloud,
        engine_settings=engine,
        executor=_fake_executor(),
    )
    assert outcome.status == "retrying"
    stored = db._find(job.id)
    assert stored is not None and stored.status == "queued"


def test_oversize_download_fails_permanently_without_executing(
    db: InMemoryWorkerDatabase,
    storage: RecordingStorage,
    cloud: CloudSettings,
    engine: MugiwaraSettings,
) -> None:
    executed: list[Any] = []

    def spy_executor(*args: Any, **kwargs: Any) -> PipelineScanOutcome:
        executed.append(args)
        raise AssertionError("executor must not run")

    job = db.add_job()
    storage.payloads[job.source_key] = b"x"
    storage.oversize_key = job.source_key
    claimed = db.claim_next_scan_job(worker_id="w", lease_seconds=600, max_attempts=3)
    assert claimed is not None
    outcome = process_job(
        claimed,
        db=db,
        storage=storage,
        cloud=cloud,
        engine_settings=engine,
        executor=spy_executor,
    )
    assert outcome.status == "failed"
    assert executed == []
    assert db.errors[job.id].startswith("object exceeds")


def test_executor_crash_sanitizes_error_and_requeues(
    db: InMemoryWorkerDatabase,
    storage: RecordingStorage,
    cloud: CloudSettings,
    engine: MugiwaraSettings,
) -> None:
    secret_detail = "leaked C:/Users/Dell/secret.txt contents abc123"

    def crashing_executor(*args: Any, **kwargs: Any) -> PipelineScanOutcome:
        raise RuntimeError(secret_detail)

    job = db.add_job()
    _seed_upload(storage, job, b"bytes")
    claimed = db.claim_next_scan_job(worker_id="w", lease_seconds=600, max_attempts=3)
    assert claimed is not None
    outcome = process_job(
        claimed,
        db=db,
        storage=storage,
        cloud=cloud,
        engine_settings=engine,
        executor=crashing_executor,
    )
    assert outcome.status == "retrying"
    recorded = db.errors[job.id]
    assert recorded == "scan failed (RuntimeError)"
    assert secret_detail not in recorded
    stored = db._find(job.id)
    assert stored is not None and stored.status == "queued"


def test_intake_rejection_message_passes_through_static_text(
    db: InMemoryWorkerDatabase,
    storage: RecordingStorage,
    cloud: CloudSettings,
    engine: MugiwaraSettings,
) -> None:
    from mugiwara.core.exceptions import ArchiveRejectedError

    def rejecting_executor(*args: Any, **kwargs: Any) -> PipelineScanOutcome:
        raise ArchiveRejectedError("archive exceeds member limit")

    job = db.add_job()
    _seed_upload(storage, job, b"bytes")
    claimed = db.claim_next_scan_job(worker_id="w", lease_seconds=600, max_attempts=3)
    assert claimed is not None
    outcome = process_job(
        claimed,
        db=db,
        storage=storage,
        cloud=cloud,
        engine_settings=engine,
        executor=rejecting_executor,
    )
    assert outcome.status == "retrying"
    assert db.errors[job.id] == (
        "source archive rejected by hardened intake: archive exceeds member limit"
    )


# -- lease-expiry crash recovery -------------------------------------------------------


def _abandon(db: InMemoryWorkerDatabase, job_id: str, *, age_seconds: int) -> None:
    """Simulate a worker crash: leave running with an already-expired lease."""
    from dataclasses import replace
    from datetime import timedelta

    row = db._find(job_id)
    assert row is not None
    db.jobs[db.jobs.index(row)] = replace(
        row,
        worker_lease_until=db._clock["now"] - timedelta(seconds=age_seconds),
    )


def test_expired_lease_requeues_preserving_attempts_then_terminalizes(
    db: InMemoryWorkerDatabase,
    storage: RecordingStorage,
    cloud: CloudSettings,
    engine: MugiwaraSettings,
) -> None:
    job = db.add_job()
    _seed_upload(storage, job, b"bytes")

    for attempt in range(1, 4):
        claimed = db.claim_next_scan_job(worker_id="w", lease_seconds=600, max_attempts=3)
        assert claimed is not None and claimed.attempts == attempt
        _abandon(db, job.id, age_seconds=700)  # crash before finishing
        recovered = run_recovery(db, max_attempts=cloud.worker_max_attempts)
        stored = db._find(job.id)
        assert stored is not None
        if attempt < 3:
            assert recovered == [job.id]
            assert stored.status == "queued"
            assert stored.attempts == attempt
        else:
            assert recovered == [job.id]
            assert stored.status == "failed"
            assert stored.attempts == 3

    final = db._find(job.id)
    assert final is not None
    assert final.status == "failed"
    assert db.claim_next_scan_job(worker_id="w", lease_seconds=60, max_attempts=3) is None


def test_recovery_ignores_active_leases_and_non_running_rows(
    db: InMemoryWorkerDatabase,
) -> None:
    fresh = db.add_job()
    claimed = db.claim_next_scan_job(worker_id="w", lease_seconds=600, max_attempts=3)
    assert claimed is not None
    queued = db.add_job(status="queued")
    assert run_recovery(db, max_attempts=3) == []
    stored_fresh = db._find(fresh.id)
    stored_queued = db._find(queued.id)
    assert stored_fresh is not None and stored_fresh.status == "running"
    assert stored_queued is not None and stored_queued.status == "queued"

    db.advance_clock(seconds=601)
    recovered = run_recovery(db, max_attempts=3)
    assert recovered == [fresh.id]


# -- state transition guards ----------------------------------------------------------


def test_complete_only_from_running_state(db: InMemoryWorkerDatabase) -> None:
    queued = db.add_job()
    cancelled = db.add_job(status="cancelled")
    assert db.complete_job(queued.id) is False
    assert db.complete_job(cancelled.id) is False
    assert db.update_job_phases(queued.id, ["x"]) is False


def test_report_insert_is_idempotent_on_conflict(db: InMemoryWorkerDatabase) -> None:
    document = build_envelope_document()
    kwargs: dict[str, Any] = {
        "owner_id": USER_A,
        "project_id": None,
        "job_id": "j",
        "origin": "archive",
        "target_label": "source.zip",
        "configuration": document["configuration"],
        "summary": document["scan"]["summary"],
        "envelope": document,
    }
    assert db.insert_report_for_job(**kwargs) is True
    assert db.insert_report_for_job(**kwargs) is False


# -- loop behavior ---------------------------------------------------------------------


def test_worker_once_returns_none_when_queue_empty(
    db: InMemoryWorkerDatabase,
    storage: RecordingStorage,
    cloud: CloudSettings,
    engine: MugiwaraSettings,
) -> None:
    outcome = run_worker_once(
        db=db,
        storage=storage,
        cloud=cloud,
        engine_settings=engine,
        executor=_fake_executor(),
    )
    assert outcome is None


def test_worker_once_claims_and_completes_one_job(
    db: InMemoryWorkerDatabase,
    storage: RecordingStorage,
    cloud: CloudSettings,
    engine: MugiwaraSettings,
) -> None:
    job = db.add_job()
    _seed_upload(storage, job, b"bytes")
    outcome = run_worker_once(
        db=db,
        storage=storage,
        cloud=cloud,
        engine_settings=engine,
        executor=_fake_executor(),
    )
    assert outcome is not None and outcome.status == "completed"
    again = run_worker_once(
        db=db,
        storage=storage,
        cloud=cloud,
        engine_settings=engine,
        executor=_fake_executor(),
    )
    assert again is None


def test_worker_loop_processes_until_stop_condition(
    db: InMemoryWorkerDatabase,
    storage: RecordingStorage,
    cloud: CloudSettings,
    engine: MugiwaraSettings,
) -> None:
    for index in range(3):
        job = db.add_job()
        _seed_upload(storage, job, f"bytes-{index}".encode())

    def should_stop() -> bool:
        return sum(1 for j in db.jobs if j.status == "completed") >= 3

    total = run_worker_loop(
        db=db,
        storage=storage,
        cloud=cloud,
        engine_settings=engine,
        executor=_fake_executor(),
        should_stop=should_stop,
    )
    assert total == 3
    assert all(j.status == "completed" for j in db.jobs)


# -- real engine integration --------------------------------------------------------------


def test_real_pipeline_mock_backend_completes_end_to_end(
    db: InMemoryWorkerDatabase,
    storage: RecordingStorage,
    cloud: CloudSettings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "mugiwara.agents.orchestrator.get_provider", lambda _config: MockLLMProvider()
    )
    archive = tmp_path / "source.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("demo/main.py", FINDING_SOURCE)
    job = db.add_job(owner_id=USER_A, scan_profile="fast")
    storage.payloads[job.source_key] = archive.read_bytes()

    engine = MugiwaraSettings(
        llm=LLMConfig(provider=LLMProviderType.MOCK),
        sandbox=SandboxConfig(mode=SandboxMode.MOCK),
    )
    outcome = run_worker_once(
        db=db,
        storage=storage,
        cloud=cloud,
        engine_settings=engine,
        workdir=tmp_path / "work",
    )

    assert outcome is not None and outcome.status == "completed"
    row = next(iter(db.reports.values()))
    parsed = parse_stored_report(json.dumps(row.envelope))
    assert parsed.schema_name == "mugiwara.scan-report"
    assert "uploads/" in parsed.scan.target_path
    assert str(tmp_path) not in json.dumps(row.envelope)
    assert db.phase_updates, "real pipeline must record phase progress"
    assert MAX_UPLOAD_BYTES > 0 and cloud.max_download_bytes <= MAX_UPLOAD_BYTES
