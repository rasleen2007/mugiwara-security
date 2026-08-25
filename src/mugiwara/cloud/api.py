"""FastAPI service exposing the Mugiwara SaaS surface (Phase 2 skeleton).

Guarantees implemented here:
- Authentication is mandatory for every route except ``/health`` and is based
  solely on a verified Supabase JWT; identity comes from the token ``sub``.
- No endpoint accepts an owner/user id from the client as authority; request
  models forbid extra fields so spoofed authority fields fail validation.
- Every persistence call passes the verified subject down to owner-scoped
  repository methods.
- The service never executes scans, never spawns workers/threads, and never
  touches Docker; it only queues jobs.
- Secrets live in ``SecretStr`` settings that are never serialized into any
  response; API docs/OpenAPI are disabled to minimize surface until the
  frontend phase introduces them deliberately.
"""

import json
import logging
import uuid as _uuid
from collections.abc import Callable
from typing import Annotated, TypeVar

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from mugiwara.cloud.auth import AuthError, CurrentUser, JwksCache, SupabaseTokenVerifier
from mugiwara.cloud.config import CloudConfigError, CloudSettings, load_settings
from mugiwara.cloud.db import Database, PostgresDatabase, ProjectRow, ReportRow, ScanJobRow
from mugiwara.cloud.queue import SubmissionError, effective_quota, enqueue_scan_job
from mugiwara.cloud.schemas import (
    EXPORT_EXTENSIONS,
    EXPORT_MEDIA_TYPES,
    ExportFormat,
    JobOut,
    MeOut,
    ProjectCreate,
    ProjectOut,
    ProjectUpdate,
    ReportOut,
    ScanJobCreate,
    SignedDownloadOut,
    SignedUploadOut,
)
from mugiwara.cloud.storage import StorageError, SupabaseStorage

log = logging.getLogger(__name__)


class DatabaseError(Exception):
    """Raised when the database is unreachable or returns an error."""

    def __init__(self, detail: str = "database temporarily unavailable") -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = 503


_T = TypeVar("_T")


def _db_call(fn: Callable[[], _T]) -> _T:
    """Execute a database call, converting psycopg errors to DatabaseError.

    Only catches psycopg/psycopg_pool errors and the pool timeout;
    programming errors (e.g. AssertionError) propagate normally.
    """
    import psycopg
    import psycopg_pool

    try:
        return fn()
    except psycopg_pool.PoolTimeout as exc:
        log.error("Database connection pool timeout")
        raise DatabaseError("database connection pool timeout") from exc
    except psycopg.Error as exc:
        msg = str(exc)
        if "password authentication failed" in msg:
            log.error("Database authentication failed — check DATABASE_URL credentials")
            raise DatabaseError("database authentication failed") from exc
        if "timeout" in msg.lower() or "connection" in msg.lower():
            log.error("Database connection failed: %s", type(exc).__name__)
            raise DatabaseError("database connection failed") from exc
        log.error("Database error: %s", type(exc).__name__)
        raise DatabaseError("database error") from exc


def get_current_user(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> CurrentUser:
    """Resolve the authenticated user from ``Authorization: Bearer <jwt>``."""
    if not authorization or not authorization.startswith("Bearer "):
        raise AuthError("missing bearer token")
    verifier: SupabaseTokenVerifier = request.app.state.verifier
    return verifier.verify(authorization[len("Bearer ") :].strip())


CurrentUserDep = Annotated[CurrentUser, Depends(get_current_user)]


def _to_job_out(row: ScanJobRow) -> JobOut:
    return JobOut(
        id=row.id,
        project_id=row.project_id,
        kind=row.kind,
        status=row.status,
        target_kind=row.target_kind,
        scan_profile=row.scan_profile,
        phases=row.phases,
        error=row.error,
        attempts=row.attempts,
        created_at=row.created_at,
        started_at=row.started_at,
        completed_at=row.completed_at,
    )


def _to_project_out(row: ProjectRow) -> ProjectOut:
    return ProjectOut(id=row.id, name=row.name, created_at=row.created_at)


def create_app(
    *,
    settings: CloudSettings,
    database: Database,
    storage: SupabaseStorage,
    verifier: SupabaseTokenVerifier,
) -> FastAPI:
    """Build the FastAPI application around injected components."""

    app = FastAPI(
        title="Mugiwara Security Cloud API",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = settings
    app.state.database = database
    app.state.storage = storage
    app.state.verifier = verifier

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

    @app.exception_handler(AuthError)
    async def _handle_auth_error(request: Request, exc: AuthError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    @app.exception_handler(SubmissionError)
    async def _handle_submission_error(request: Request, exc: SubmissionError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    @app.exception_handler(DatabaseError)
    async def _handle_database_error(request: Request, exc: DatabaseError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    @app.exception_handler(StorageError)
    async def _handle_storage_error(request: Request, exc: StorageError) -> JSONResponse:
        return JSONResponse(status_code=502, content={"detail": "storage service error"})

    @app.exception_handler(Exception)
    async def _handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(status_code=500, content={"detail": "internal server error"})

    @app.exception_handler(HTTPException)
    async def _handle_http_exception(request: Request, exc: HTTPException) -> JSONResponse:
        detail = exc.detail if isinstance(exc.detail, str) else "request rejected"
        return JSONResponse(status_code=exc.status_code, content={"detail": detail})

    @app.get("/health")
    def health() -> dict[str, str]:
        db_ok = True
        try:
            database.check_connectivity()
        except Exception:
            db_ok = False
        status = "ok" if db_ok else "degraded"
        result: dict[str, str] = {"status": status, "service": "mugiwara-cloud-api"}
        if not db_ok:
            result["database"] = "unreachable"
        return result

    @app.get("/api/me")
    def me(user: CurrentUserDep) -> MeOut:
        return MeOut(user_id=user.user_id, email=user.email, role=user.role)

    # -- projects -------------------------------------------------------------

    @app.post("/api/projects", status_code=201)
    def create_project(user: CurrentUserDep, payload: ProjectCreate) -> ProjectOut:
        row = _db_call(lambda: database.create_project(user.user_id, payload.name))
        return _to_project_out(row)

    @app.get("/api/projects")
    def list_projects(
        user: CurrentUserDep, limit: Annotated[int, Query(ge=1, le=100)] = 20
    ) -> list[ProjectOut]:
        rows = _db_call(lambda: database.list_projects(user.user_id, limit))
        return [_to_project_out(row) for row in rows]

    @app.get("/api/projects/{project_id}")
    def get_project(user: CurrentUserDep, project_id: str) -> ProjectOut:
        row = _db_call(lambda: database.get_project(user.user_id, project_id))
        if row is None:
            raise HTTPException(status_code=404, detail="project not found")
        return _to_project_out(row)

    @app.patch("/api/projects/{project_id}")
    def rename_project(user: CurrentUserDep, project_id: str, payload: ProjectUpdate) -> ProjectOut:
        row = _db_call(lambda: database.update_project(user.user_id, project_id, payload.name))
        if row is None:
            raise HTTPException(status_code=404, detail="project not found")
        return _to_project_out(row)

    @app.delete("/api/projects/{project_id}", status_code=204)
    def delete_project(user: CurrentUserDep, project_id: str) -> Response:
        if not _db_call(lambda: database.delete_project(user.user_id, project_id)):
            raise HTTPException(status_code=404, detail="project not found")
        return Response(status_code=204)

    # -- uploads --------------------------------------------------------------

    @app.post("/api/uploads/sign")
    def sign_upload(user: CurrentUserDep) -> SignedUploadOut:
        job_id = str(_uuid.uuid4())
        url, path = storage.signed_upload_url(user.user_id, job_id, settings.upload_url_ttl_seconds)
        return SignedUploadOut(
            path=path,
            upload_url=url,
            expires_in=settings.upload_url_ttl_seconds,
        )

    # -- scan jobs ------------------------------------------------------------

    @app.post("/api/jobs", status_code=201)
    def create_job(user: CurrentUserDep, payload: ScanJobCreate) -> JobOut:
        row = _db_call(
            lambda: enqueue_scan_job(
                database,
                owner_id=user.user_id,
                upload_path=payload.upload_path,
                project_id=payload.project_id,
                scan_profile=payload.scan_profile.value,
                source_bytes=payload.source_bytes,
                source_sha256=payload.source_sha256,
            )
        )
        return _to_job_out(row)

    @app.get("/api/jobs")
    def list_jobs(
        user: CurrentUserDep,
        limit: Annotated[int, Query(ge=1, le=100)] = 20,
        status_filter: Annotated[str | None, Query(alias="status")] = None,
    ) -> list[JobOut]:
        rows = _db_call(lambda: database.list_jobs(user.user_id, status=status_filter, limit=limit))
        return [_to_job_out(row) for row in rows]

    @app.get("/api/jobs/{job_id}")
    def get_job(user: CurrentUserDep, job_id: str) -> JobOut:
        row = _db_call(lambda: database.get_job(user.user_id, job_id))
        if row is None:
            raise HTTPException(status_code=404, detail="job not found")
        return _to_job_out(row)

    @app.post("/api/jobs/{job_id}/cancel")
    def cancel_job(user: CurrentUserDep, job_id: str) -> JobOut:
        row = _db_call(lambda: database.get_job(user.user_id, job_id))
        if row is None:
            raise HTTPException(status_code=404, detail="job not found")
        if row.status != "queued":
            raise HTTPException(status_code=409, detail="only queued jobs can be cancelled")
        if not _db_call(lambda: database.cancel_queued_job(user.user_id, job_id)):
            raise HTTPException(status_code=409, detail="job left the queue before cancellation")
        updated = _db_call(lambda: database.get_job(user.user_id, job_id))
        assert updated is not None
        return _to_job_out(updated)

    @app.get("/api/jobs/{job_id}/source-url")
    def job_source_url(user: CurrentUserDep, job_id: str) -> SignedDownloadOut:
        row = _db_call(lambda: database.get_job(user.user_id, job_id))
        if row is None:
            raise HTTPException(status_code=404, detail="job not found")
        url = storage.signed_download_url(
            row.source_bucket, row.source_key, settings.download_url_ttl_seconds
        )
        return SignedDownloadOut(download_url=url, expires_in=settings.download_url_ttl_seconds)

    # -- reports --------------------------------------------------------------

    @app.get("/api/reports")
    def list_reports(
        user: CurrentUserDep,
        limit: Annotated[int, Query(ge=1, le=100)] = 20,
        project_id: str | None = None,
    ) -> list[ReportOut]:
        if project_id is not None:
            _require_uuid(project_id)
        rows = _db_call(
            lambda: database.list_reports(user.user_id, project_id=project_id, limit=limit)
        )
        return [_report_out(row) for row in rows]

    @app.get("/api/reports/{report_id}")
    def get_report(user: CurrentUserDep, report_id: str) -> ReportOut:
        row = _db_call(lambda: database.get_report(user.user_id, report_id))
        if row is None:
            raise HTTPException(status_code=404, detail="report not found")
        return _report_out(row)

    @app.get("/api/reports/{report_id}/export")
    def export_report(
        user: CurrentUserDep,
        report_id: str,
        fmt: Annotated[ExportFormat, Query(alias="format")] = ExportFormat.MARKDOWN,
    ) -> Response:
        row = _db_call(lambda: database.get_report(user.user_id, report_id))
        if row is None:
            raise HTTPException(status_code=404, detail="report not found")

        from mugiwara.exporters.markdown import export_report_to_markdown
        from mugiwara.exporters.sarif import render_sarif
        from mugiwara.reports.store import (
            ReportFormatError,
            ReportInvalidContentsError,
            UnsupportedSchemaError,
            parse_stored_report,
        )

        raw = json.dumps(row.envelope)
        try:
            stored = parse_stored_report(raw)
        except (ReportFormatError, ReportInvalidContentsError, UnsupportedSchemaError) as exc:
            raise HTTPException(status_code=500, detail="stored report unreadable") from exc

        if fmt is ExportFormat.MARKDOWN:
            body: str = export_report_to_markdown(stored.scan)
        elif fmt is ExportFormat.SARIF:
            body = render_sarif(stored.scan)
        else:
            body = raw
        filename = f"{row.report_id}.{EXPORT_EXTENSIONS[fmt]}"
        return Response(
            content=body,
            media_type=EXPORT_MEDIA_TYPES[fmt],
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    # -- quota visibility -----------------------------------------------------

    @app.get("/api/quota")
    def show_quota(user: CurrentUserDep) -> dict[str, int]:
        quota = _db_call(lambda: effective_quota(database, user.user_id))
        return {
            "max_concurrent_running_jobs": quota.max_concurrent_running_jobs,
            "max_queued_jobs": quota.max_queued_jobs,
            "max_source_bytes": quota.max_source_bytes,
            "max_jobs_per_day": quota.max_jobs_per_day,
        }

    return app


def _report_out(row: ReportRow) -> ReportOut:
    return ReportOut(
        report_id=row.report_id,
        project_id=row.project_id,
        origin=row.origin,
        target_label=row.target_label,
        summary=dict(row.summary),
        created_at=row.created_at,
    )


def _require_uuid(value: str) -> None:
    try:
        _uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid identifier") from exc


# ---------------------------------------------------------------------------
# Module-level application instance
# ---------------------------------------------------------------------------

# ``uvicorn mugiwara.cloud.api:app`` expects a module-level ``app`` object.
# We build it lazily so that importing this module (e.g. for tests) does not
# require environment variables to be set — the real build happens on first
# attribute access.

_app: FastAPI | None = None


def _get_app() -> FastAPI:
    """Lazily construct and cache the FastAPI application."""
    global _app  # noqa: PLW0603
    if _app is not None:
        return _app
    settings = load_settings()
    database = PostgresDatabase(
        settings.database_url.get_secret_value(),
        connect_timeout=settings.db_connect_timeout,
    )
    storage = SupabaseStorage(
        base_url=settings.supabase_url,
        service_key=settings.supabase_service_role_key,
        upload_bucket=settings.upload_bucket,
        export_bucket=settings.export_bucket,
        timeout_seconds=settings.http_timeout_seconds,
    )
    cache = JwksCache(
        settings.jwks_url,
        ttl_seconds=settings.jwks_cache_ttl_seconds,
        min_refresh_seconds=settings.jwks_min_refresh_seconds,
    )
    verifier = SupabaseTokenVerifier(
        cache,
        issuer=settings.issuer,
        audience=settings.jwt_audience,
        leeway_seconds=settings.jwt_leeway_seconds,
    )
    _app = create_app(settings=settings, database=database, storage=storage, verifier=verifier)
    return _app


def __getattr__(name: str) -> FastAPI:
    """Module-level lazy loader for ``app``."""
    if name == "app":
        return _get_app()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["create_app", "main", "app"]  # noqa: F822


def main() -> None:
    """Run the API locally/hosted; loopback binding unless overridden.

    Launches uvicorn as a *subprocess* to avoid nested event-loop issues
    (``asyncio.run()`` cannot be called from an already running loop).
    """
    import os
    import subprocess
    import sys

    try:
        load_settings()
    except CloudConfigError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from exc

    host = os.environ.get("MUGIWARA_CLOUD_API_HOST", "127.0.0.1")
    port = int(os.environ.get("MUGIWARA_CLOUD_API_PORT", "8000"))
    workers = int(os.environ.get("MUGIWARA_CLOUD_API_WORKERS", "1"))
    reload = os.environ.get("MUGIWARA_CLOUD_API_RELOAD", "").lower() in ("1", "true", "yes")
    log_level = os.environ.get("MUGIWARA_CLOUD_LOG_LEVEL", "info").lower()

    log.info(
        "Starting Mugiwara Cloud API (host=%s, port=%d, workers=%d)",
        host,
        port,
        workers,
    )

    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "mugiwara.cloud.api:app",
        "--host",
        host,
        "--port",
        str(port),
        "--workers",
        str(workers),
        "--log-level",
        log_level,
    ]

    if reload:
        cmd.append("--reload")

    subprocess.run(cmd, check=True)
