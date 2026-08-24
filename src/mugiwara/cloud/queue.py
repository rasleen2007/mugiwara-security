"""Scan-job submission pipeline: path validation, quotas, queued inserts.

The API never executes scans. Its only job-queue interaction is inserting a
row in ``queued`` state after enforcing per-user quotas, so the Phase 3
worker can claim work with ``FOR UPDATE SKIP LOCKED``.
"""

import uuid
from datetime import datetime, timezone

from mugiwara.cloud.config import MAX_UPLOAD_BYTES
from mugiwara.cloud.db import DEFAULT_QUOTA, Database, QuotaRow, ScanJobRow

ACTIVE_STATUSES = ("queued", "running")
TODAY_STATUSES = ("queued", "running", "completed", "failed", "cancelled")


class SubmissionError(Exception):
    """Client-visible submission failure."""

    def __init__(self, detail: str, status_code: int) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


class UploadPathRejectedError(SubmissionError):
    def __init__(self) -> None:
        super().__init__(
            "upload_path must be the server-issued path for your account",
            400,
        )


class ProjectNotFoundError(SubmissionError):
    def __init__(self) -> None:
        super().__init__("project not found", 404)


class QueueCapacityReachedError(SubmissionError):
    def __init__(self) -> None:
        super().__init__("queue capacity reached; retry when jobs finish", 409)


class DailyQuotaExceededError(SubmissionError):
    def __init__(self) -> None:
        super().__init__("daily job quota exceeded", 429)


class SourceTooLargeError(SubmissionError):
    def __init__(self) -> None:
        super().__init__("source archive exceeds your size limit", 413)


def effective_quota(db: Database, user_id: str) -> QuotaRow:
    return db.get_quota(user_id) or DEFAULT_QUOTA


def enqueue_scan_job(
    db: Database,
    *,
    owner_id: str,
    upload_path: str,
    project_id: str | None = None,
    scan_profile: str = "standard",
    source_bytes: int | None = None,
    source_sha256: str | None = None,
    now: datetime | None = None,
) -> ScanJobRow:
    """Validate and insert a new queued scan job for ``owner_id``.

    The storage key is accepted only after :func:`canonical_upload_path`
    proves it lives inside the caller's own namespace, and the resulting row
    is always created in ``queued`` status owned by the verified subject.
    """
    from mugiwara.cloud.storage import canonical_upload_path

    try:
        source_key = canonical_upload_path(owner_id, upload_path)
    except ValueError as exc:
        raise UploadPathRejectedError from exc

    if project_id is not None and db.get_project(owner_id, project_id) is None:
        raise ProjectNotFoundError

    quota = effective_quota(db, owner_id)
    if db.count_jobs(owner_id, ACTIVE_STATUSES) >= (
        quota.max_concurrent_running_jobs + quota.max_queued_jobs
    ):
        raise QueueCapacityReachedError
    if db.count_jobs_today(owner_id) >= quota.max_jobs_per_day:
        raise DailyQuotaExceededError
    cap = min(quota.max_source_bytes, MAX_UPLOAD_BYTES)
    if source_bytes is not None and source_bytes > cap:
        raise SourceTooLargeError

    return db.insert_scan_job(
        owner_id=owner_id,
        job_id=str(uuid.uuid4()),
        project_id=project_id,
        kind="scan",
        target_kind="zip",
        source_bucket="scan-uploads",
        source_key=source_key,
        source_sha256=source_sha256,
        source_bytes=source_bytes,
        scan_profile=scan_profile,
    )


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
