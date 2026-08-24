"""Database access for the cloud API.

Two layers:
- :class:`Database`: a protocol whose every method takes an explicit
  ``owner_id`` and filters by it. The API layer only ever passes the verified
  JWT subject, which makes cross-user (IDOR) access structurally impossible.
- :class:`PostgresDatabase`: a psycopg-backed implementation of that protocol
  against the Supabase Postgres instance. It connects with the service-role
  DSN (which bypasses RLS), so the explicit ``owner_id = %s`` predicates here
  are the real security boundary, defense in depth alongside RLS.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol


@dataclass(frozen=True)
class ProjectRow:
    id: str
    owner_id: str
    name: str
    created_at: datetime


@dataclass(frozen=True)
class ScanJobRow:
    id: str
    owner_id: str
    project_id: str | None
    kind: str
    status: str
    target_kind: str
    source_bucket: str
    source_key: str
    source_sha256: str | None
    source_bytes: int | None
    scan_profile: str
    phases: list[str]
    error: str | None
    attempts: int
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    worker_id: str | None = None
    worker_lease_until: datetime | None = None


@dataclass(frozen=True)
class ReportRow:
    report_id: str
    owner_id: str
    project_id: str | None
    origin: str
    target_label: str
    summary: dict[str, Any]
    envelope: dict[str, Any]
    created_at: datetime


@dataclass(frozen=True)
class QuotaRow:
    max_concurrent_running_jobs: int
    max_queued_jobs: int
    max_source_bytes: int
    max_jobs_per_day: int


DEFAULT_QUOTA = QuotaRow(
    max_concurrent_running_jobs=2,
    max_queued_jobs=10,
    max_source_bytes=536870912,
    max_jobs_per_day=50,
)

_JOB_COLUMNS = (
    "id, owner_id, project_id, kind, status, target_kind, source_bucket, "
    "source_key, source_sha256, source_bytes, scan_profile, phases, error, "
    "attempts, created_at, started_at, completed_at"
)

_CLAIM_COLUMNS = f"{_JOB_COLUMNS}, worker_id, worker_lease_until"

# Atomic claim: FOR UPDATE SKIP LOCKED guarantees exactly one worker wins a
# row even with many concurrent workers; attempts < cap bounds crash retries.
CLAIM_SCAN_JOB_SQL = (
    "update public.scan_jobs set "
    "status = 'running', started_at = now(), worker_id = %s, "
    "worker_lease_until = now() + make_interval(secs => %s), "
    "attempts = attempts + 1, error = null "
    "where id in ("
    "select id from public.scan_jobs "
    "where status = 'queued' and kind = 'scan' and attempts < %s "
    "order by created_at "
    "for update skip locked limit 1) "
    f"returning {_CLAIM_COLUMNS}"
)

RECOVER_EXPIRED_LEASES_SQL = (
    "update public.scan_jobs set status = 'failed', "
    "completed_at = now(), worker_id = null, worker_lease_until = null, "
    "error = coalesce(error, 'lease expired after repeated crashes') "
    "where status = 'running' and worker_lease_until is not null "
    "and worker_lease_until < now() and attempts >= %s "
    "returning id"
)

REQUEUE_EXPIRED_LEASES_SQL = (
    "update public.scan_jobs set status = 'queued', "
    "started_at = null, worker_id = null, worker_lease_until = null "
    "where status = 'running' and worker_lease_until is not null "
    "and worker_lease_until < now() and attempts < %s "
    "returning id"
)


def _phases(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    return [str(item) for item in raw]


def _job_row(row: Mapping[str, Any]) -> ScanJobRow:
    return ScanJobRow(
        id=str(row["id"]),
        owner_id=str(row["owner_id"]),
        project_id=str(row["project_id"]) if row["project_id"] is not None else None,
        kind=str(row["kind"]),
        status=str(row["status"]),
        target_kind=str(row["target_kind"]),
        source_bucket=str(row["source_bucket"]),
        source_key=str(row["source_key"]),
        source_sha256=row["source_sha256"]
        if row["source_sha256"] is None
        else str(row["source_sha256"]),
        source_bytes=row["source_bytes"] if row["source_bytes"] is not None else None,
        scan_profile=str(row["scan_profile"]),
        phases=_phases(row["phases"]),
        error=row["error"] if row["error"] is None else str(row["error"]),
        attempts=int(row["attempts"]),
        created_at=row["created_at"],
        started_at=row["started_at"],
        completed_at=row["completed_at"],
        worker_id=str(row["worker_id"]) if row.get("worker_id") is not None else None,
        worker_lease_until=row.get("worker_lease_until"),
    )


class Database(Protocol):
    """Persistence boundary; every method is owner-scoped by contract."""

    def create_project(self, owner_id: str, name: str) -> ProjectRow: ...

    def list_projects(self, owner_id: str, limit: int) -> list[ProjectRow]: ...

    def get_project(self, owner_id: str, project_id: str) -> ProjectRow | None: ...

    def update_project(self, owner_id: str, project_id: str, name: str) -> ProjectRow | None: ...

    def delete_project(self, owner_id: str, project_id: str) -> bool: ...

    def insert_scan_job(
        self,
        *,
        owner_id: str,
        job_id: str,
        project_id: str | None,
        kind: str,
        target_kind: str,
        source_bucket: str,
        source_key: str,
        source_sha256: str | None,
        source_bytes: int | None,
        scan_profile: str,
    ) -> ScanJobRow: ...

    def get_job(self, owner_id: str, job_id: str) -> ScanJobRow | None: ...

    def list_jobs(
        self, owner_id: str, *, status: str | None = None, limit: int = 20
    ) -> list[ScanJobRow]: ...

    def count_jobs(self, owner_id: str, statuses: Sequence[str]) -> int: ...

    def count_jobs_today(self, owner_id: str) -> int: ...

    def cancel_queued_job(self, owner_id: str, job_id: str) -> bool: ...

    def get_quota(self, user_id: str) -> QuotaRow | None: ...

    def get_report(self, owner_id: str, report_id: str) -> ReportRow | None: ...

    def list_reports(
        self, owner_id: str, *, project_id: str | None = None, limit: int = 20
    ) -> list[ReportRow]: ...


class PostgresDatabase:
    """Service-role psycopg implementation of :class:`Database`.

    Every statement parameterizes ``owner_id``/``user_id`` from the value
    supplied by the API layer (the verified JWT subject). No method accepts a
    table or column identifier; no string formatting enters SQL text.
    """

    def __init__(self, dsn: str, *, pool_size: int = 4) -> None:
        from psycopg_pool import ConnectionPool

        self._pool: ConnectionPool = ConnectionPool(
            dsn,
            min_size=1,
            max_size=pool_size,
            kwargs={"autocommit": True},
            open=True,
        )

    def close(self) -> None:
        self._pool.close()

    @staticmethod
    def _cursor(conn: Any) -> Any:
        from psycopg.rows import dict_row

        return conn.cursor(row_factory=dict_row)

    def _fetchone(self, sql: str, params: tuple[Any, ...]) -> dict[str, Any] | None:
        with self._pool.connection() as conn, self._cursor(conn) as cur:
            cur.execute(sql, params)
            row = cur.fetchone()
        return dict(row) if row is not None else None

    def _execute_returning(self, sql: str, params: tuple[Any, ...]) -> dict[str, Any] | None:
        with self._pool.connection() as conn, self._cursor(conn) as cur:
            cur.execute(sql, params)
            row = cur.fetchone()
        return dict(row) if row is not None else None

    # -- projects ------------------------------------------------------------

    def create_project(self, owner_id: str, name: str) -> ProjectRow:
        row = self._execute_returning(
            "insert into public.projects (owner_id, name) values (%s, %s) "
            "returning id, owner_id, name, created_at",
            (owner_id, name),
        )
        assert row is not None
        return ProjectRow(
            id=str(row["id"]),
            owner_id=str(row["owner_id"]),
            name=str(row["name"]),
            created_at=row["created_at"],
        )

    def list_projects(self, owner_id: str, limit: int) -> list[ProjectRow]:
        rows: list[ProjectRow] = []
        with self._pool.connection() as conn, self._cursor(conn) as cur:
            cur.execute(
                "select id, owner_id, name, created_at from public.projects "
                "where owner_id = %s order by created_at desc limit %s",
                (owner_id, limit),
            )
            for row in cur.fetchall():
                rows.append(
                    ProjectRow(
                        id=str(row["id"]),
                        owner_id=str(row["owner_id"]),
                        name=str(row["name"]),
                        created_at=row["created_at"],
                    )
                )
        return rows

    def get_project(self, owner_id: str, project_id: str) -> ProjectRow | None:
        row = self._fetchone(
            "select id, owner_id, name, created_at from public.projects "
            "where id = %s and owner_id = %s",
            (project_id, owner_id),
        )
        if row is None:
            return None
        return ProjectRow(
            id=str(row["id"]),
            owner_id=str(row["owner_id"]),
            name=str(row["name"]),
            created_at=row["created_at"],
        )

    def update_project(self, owner_id: str, project_id: str, name: str) -> ProjectRow | None:
        row = self._execute_returning(
            "update public.projects set name = %s where id = %s and owner_id = %s "
            "returning id, owner_id, name, created_at",
            (name, project_id, owner_id),
        )
        if row is None:
            return None
        return ProjectRow(
            id=str(row["id"]),
            owner_id=str(row["owner_id"]),
            name=str(row["name"]),
            created_at=row["created_at"],
        )

    def delete_project(self, owner_id: str, project_id: str) -> bool:
        row = self._execute_returning(
            "delete from public.projects where id = %s and owner_id = %s returning id",
            (project_id, owner_id),
        )
        return row is not None

    # -- scan jobs -----------------------------------------------------------

    def insert_scan_job(
        self,
        *,
        owner_id: str,
        job_id: str,
        project_id: str | None,
        kind: str,
        target_kind: str,
        source_bucket: str,
        source_key: str,
        source_sha256: str | None,
        source_bytes: int | None,
        scan_profile: str,
    ) -> ScanJobRow:
        from psycopg.types.json import Json

        row = self._execute_returning(
            f"insert into public.scan_jobs "
            f"(id, owner_id, project_id, kind, status, target_kind, source_bucket, "
            f"source_key, source_sha256, source_bytes, scan_profile, phases) "
            f"            values (%s, %s, %s, %s, 'queued', %s, %s, %s, %s, %s, %s, %s) "
            f"returning {_JOB_COLUMNS}",
            (
                job_id,
                owner_id,
                project_id,
                kind,
                target_kind,
                source_bucket,
                source_key,
                source_sha256,
                source_bytes,
                scan_profile,
                Json([]),
            ),
        )
        assert row is not None
        return _job_row(row)

    def get_job(self, owner_id: str, job_id: str) -> ScanJobRow | None:
        row = self._fetchone(
            f"select {_JOB_COLUMNS} from public.scan_jobs where id = %s and owner_id = %s",
            (job_id, owner_id),
        )
        return _job_row(row) if row is not None else None

    def list_jobs(
        self, owner_id: str, *, status: str | None = None, limit: int = 20
    ) -> list[ScanJobRow]:
        jobs: list[ScanJobRow] = []
        sql: str
        params: tuple[Any, ...]
        base = f"select {_JOB_COLUMNS} from public.scan_jobs where owner_id = %s"
        if status is None:
            sql = base + " order by created_at desc limit %s"
            params = (owner_id, limit)
        else:
            sql = base + " and status = %s order by created_at desc limit %s"
            params = (owner_id, status, limit)
        with self._pool.connection() as conn, self._cursor(conn) as cur:
            cur.execute(sql, params)
            jobs.extend(_job_row(dict(row)) for row in cur.fetchall())
        return jobs

    def count_jobs(self, owner_id: str, statuses: Sequence[str]) -> int:
        row = self._fetchone(
            "select count(*) as n from public.scan_jobs where owner_id = %s and status = any(%s)",
            (owner_id, list(statuses)),
        )
        assert row is not None
        return int(row["n"])

    def count_jobs_today(self, owner_id: str) -> int:
        row = self._fetchone(
            "select count(*) as n from public.scan_jobs where owner_id = %s "
            "and created_at >= date_trunc('day', now() at time zone 'utc')",
            (owner_id,),
        )
        assert row is not None
        return int(row["n"])

    def cancel_queued_job(self, owner_id: str, job_id: str) -> bool:
        row = self._execute_returning(
            "update public.scan_jobs set status = 'cancelled', completed_at = now() "
            "where id = %s and owner_id = %s and status = 'queued' returning id",
            (job_id, owner_id),
        )
        return row is not None

    def get_quota(self, user_id: str) -> QuotaRow | None:
        row = self._fetchone(
            "select max_concurrent_running_jobs, max_queued_jobs, max_source_bytes, "
            "max_jobs_per_day from public.user_quotas where user_id = %s",
            (user_id,),
        )
        if row is None:
            return None
        return QuotaRow(
            max_concurrent_running_jobs=int(row["max_concurrent_running_jobs"]),
            max_queued_jobs=int(row["max_queued_jobs"]),
            max_source_bytes=int(row["max_source_bytes"]),
            max_jobs_per_day=int(row["max_jobs_per_day"]),
        )

    # -- reports -------------------------------------------------------------

    def get_report(self, owner_id: str, report_id: str) -> ReportRow | None:
        row = self._fetchone(
            "select report_id, owner_id, project_id, origin, target_label, summary, "
            "envelope, created_at from public.reports "
            "where report_id = %s and owner_id = %s",
            (report_id, owner_id),
        )
        return _report_row(row) if row is not None else None

    def list_reports(
        self, owner_id: str, *, project_id: str | None = None, limit: int = 20
    ) -> list[ReportRow]:
        reports: list[ReportRow] = []
        sql: str
        params: tuple[Any, ...]
        base = (
            "select report_id, owner_id, project_id, origin, target_label, summary, "
            "envelope, created_at from public.reports where owner_id = %s"
        )
        if project_id is None:
            sql = base + " order by created_at desc limit %s"
            params = (owner_id, limit)
        else:
            sql = base + " and project_id = %s order by created_at desc limit %s"
            params = (owner_id, project_id, limit)
        with self._pool.connection() as conn, self._cursor(conn) as cur:
            cur.execute(sql, params)
            reports.extend(_report_row(dict(row)) for row in cur.fetchall())
        return reports

    # -- worker operations ----------------------------------------------------
    # These are infrastructure operations issued with the service role and are
    # intentionally NOT part of the owner-scoped Database protocol. Owner
    # isolation is preserved because every report row is inserted with the
    # owner_id copied from its job, and the worker validates that the storage
    # key namespace matches that owner before downloading anything.

    def claim_next_scan_job(
        self, *, worker_id: str, lease_seconds: int, max_attempts: int
    ) -> ScanJobRow | None:
        row = self._execute_returning(
            CLAIM_SCAN_JOB_SQL, (worker_id, float(lease_seconds), max_attempts)
        )
        return _job_row(row) if row is not None else None

    def update_job_phases(self, job_id: str, phases: list[str]) -> bool:
        from psycopg.types.json import Json

        row = self._execute_returning(
            "update public.scan_jobs set phases = %s "
            "where id = %s and status = 'running' returning id",
            (Json(phases), job_id),
        )
        return row is not None

    def complete_job(self, job_id: str) -> bool:
        row = self._execute_returning(
            "update public.scan_jobs set status = 'completed', "
            "completed_at = now(), worker_lease_until = null "
            "where id = %s and status = 'running' returning id",
            (job_id,),
        )
        return row is not None

    def fail_job(self, job_id: str, error: str, *, retry: bool) -> str | None:
        if retry:
            row = self._execute_returning(
                "update public.scan_jobs set status = 'queued', worker_id = null, "
                "worker_lease_until = null, started_at = null, error = %s "
                "where id = %s and status = 'running' returning status",
                (error, job_id),
            )
        else:
            row = self._execute_returning(
                "update public.scan_jobs set status = 'failed', "
                "completed_at = now(), worker_lease_until = null, error = %s "
                "where id = %s and status in ('running', 'queued') returning status",
                (error, job_id),
            )
        return str(row["status"]) if row is not None else None

    def recover_expired_leases(self, *, max_attempts: int) -> list[str]:
        """Requeue crashed jobs with retries left; fail exhausted ones."""
        ids: list[str] = []
        with self._pool.connection() as conn, self._cursor(conn) as cur:
            cur.execute(RECOVER_EXPIRED_LEASES_SQL, (max_attempts,))
            ids.extend(str(row["id"]) for row in cur.fetchall())
            cur.execute(REQUEUE_EXPIRED_LEASES_SQL, (max_attempts,))
            ids.extend(str(row["id"]) for row in cur.fetchall())
        return ids

    def insert_report_for_job(
        self,
        *,
        owner_id: str,
        project_id: str | None,
        job_id: str,
        origin: str,
        target_label: str,
        configuration: dict[str, Any],
        summary: dict[str, Any],
        envelope: dict[str, Any],
    ) -> bool:
        """Insert one scan-report row; returns False when it already exists."""
        from psycopg.types.json import Json

        row = self._execute_returning(
            "insert into public.reports "
            "(report_id, owner_id, project_id, job_id, origin, target_label, "
            "configuration, summary, envelope) values (%s, %s, %s, %s, %s, %s, %s, %s, %s) "
            "on conflict (report_id) do nothing returning report_id",
            (
                envelope["report_id"],
                owner_id,
                project_id,
                job_id,
                origin,
                target_label,
                Json(dict(configuration)),
                Json(dict(summary)),
                Json(dict(envelope)),
            ),
        )
        return row is not None


def _report_row(row: Mapping[str, Any]) -> ReportRow:
    summary = row["summary"] if isinstance(row["summary"], dict) else {}
    envelope = row["envelope"] if isinstance(row["envelope"], dict) else {}
    return ReportRow(
        report_id=str(row["report_id"]),
        owner_id=str(row["owner_id"]),
        project_id=row["project_id"] if row["project_id"] is None else str(row["project_id"]),
        origin=str(row["origin"]),
        target_label=str(row["target_label"]),
        summary=dict(summary),
        envelope=dict(envelope),
        created_at=row["created_at"],
    )
