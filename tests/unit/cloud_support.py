"""Shared hermetic fixtures for the cloud API tests.

Provides:
- a session-wide RSA keypair plus JWKS documents for real signature checks,
- deterministic Supabase-style token minting (RS256/HS256, claim overrides),
- an ``InMemoryDatabase`` implementing the owner-scoped ``Database`` protocol,
- a ``RecordingStorage`` double that captures bucket/key/ttl arguments,
- a :func:`make_app` factory wiring real ``create_app`` with these doubles.
"""

import json
import threading
import uuid as _uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from pydantic import SecretStr

from mugiwara.cloud.api import create_app
from mugiwara.cloud.auth import JwksCache, SupabaseTokenVerifier
from mugiwara.cloud.config import CloudSettings
from mugiwara.cloud.db import ProjectRow, QuotaRow, ReportRow, ScanJobRow
from mugiwara.cloud.queue import utc_now

ISSUER = "https://auth.example.test/auth/v1"
JWKS_URL = f"{ISSUER}/.well-known/jwks.json"
AUDIENCE = "authenticated"
SERVICE_KEY_VALUE = "svc-role-secret-value-do-not-leak-0123456789"

USER_A = "11111111-1111-4111-8111-111111111111"
USER_B = "22222222-2222-4222-8222-222222222222"


@lru_cache(maxsize=1)
def _rsa_pair(name: str) -> tuple[bytes, dict[str, Any]]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    jwk_obj: dict[str, Any] | str = jwt.algorithms.RSAAlgorithm.to_jwk(
        key.public_key(), as_dict=True
    )
    jwk: dict[str, Any] = json.loads(jwk_obj) if isinstance(jwk_obj, str) else dict(jwk_obj)
    jwk.update({"use": "sig", "alg": "RS256"})
    return pem, jwk


def primary_key() -> tuple[bytes, dict[str, Any]]:
    return _rsa_pair("primary")


def rogue_key() -> tuple[bytes, dict[str, Any]]:
    return _rsa_pair("rogue")


class RotatingJwks:
    """Fetch double serving a controllable set of signing keys."""

    def __init__(self) -> None:
        _, jwk = primary_key()
        self.published: list[dict[str, Any]] = [dict(jwk, kid="kid-1")]
        self.calls = 0
        self.fail_next = False
        self._lock = threading.Lock()

    def fetch(self, _url: str) -> dict[str, Any]:
        with self._lock:
            self.calls += 1
            if self.fail_next:
                self.fail_next = False
                msg = "boom"
                raise RuntimeError(msg)
            return {"keys": [dict(k) for k in self.published]}


def make_token(
    sub: str = USER_A,
    *,
    claims: dict[str, Any] | None = None,
    signing_pem: bytes | None = None,
    kid: str | None = "kid-1",
    algorithm: str = "RS256",
    hmac_secret: str = "attacker-controlled-hmac-secret-at-least-32-bytes",
) -> str:
    now = int(datetime.now(tz=UTC).timestamp())
    payload: dict[str, Any] = {
        "sub": sub,
        "email": f"{sub[:2]}@example.test",
        "role": AUDIENCE,
        "aud": [AUDIENCE],
        "iss": ISSUER,
        "iat": now,
        "exp": now + 600,
    }
    if claims:
        payload.update(claims)
    for absent in [k for k, v in payload.items() if v is None]:
        payload.pop(absent)
    if algorithm == "HS256":
        return jwt.encode(payload, hmac_secret, algorithm=algorithm)
    pem = signing_pem if signing_pem is not None else primary_key()[0]
    return jwt.encode(payload, pem, algorithm=algorithm, headers={"kid": kid})


class InMemoryDatabase:
    """Minimal owner-scoped persistence double."""

    def __init__(self) -> None:
        self.projects: dict[tuple[str, str], ProjectRow] = {}
        self.jobs: list[ScanJobRow] = []
        self.reports: dict[tuple[str, str], ReportRow] = {}
        self.quotas: dict[str, QuotaRow] = {}

    def set_quota(self, user_id: str, quota: QuotaRow) -> None:
        self.quotas[user_id] = quota

    def put_report(self, row: ReportRow) -> None:
        self.reports[(row.owner_id, row.report_id)] = row

    def add_job(self, **overrides: Any) -> ScanJobRow:
        row = ScanJobRow(
            id=str(_uuid.uuid4()),
            owner_id=USER_B,
            project_id=None,
            kind="scan",
            status="queued",
            target_kind="zip",
            source_bucket="scan-uploads",
            source_key=f"{USER_B}/{_uuid.uuid4()}/source.zip",
            source_sha256=None,
            source_bytes=1024,
            scan_profile="standard",
            phases=[],
            error=None,
            attempts=0,
            created_at=utc_now(),
            started_at=None,
            completed_at=None,
        )
        row = replace(row, **overrides)
        self.jobs.append(row)
        return row

    # -- Database protocol ----------------------------------------------------

    def create_project(self, owner_id: str, name: str) -> ProjectRow:
        row = ProjectRow(id=str(_uuid.uuid4()), owner_id=owner_id, name=name, created_at=utc_now())
        self.projects[(owner_id, row.id)] = row
        return row

    def list_projects(self, owner_id: str, limit: int) -> list[ProjectRow]:
        rows = [r for (o, _), r in self.projects.items() if o == owner_id]
        return sorted(rows, key=lambda r: r.created_at, reverse=True)[:limit]

    def get_project(self, owner_id: str, project_id: str) -> ProjectRow | None:
        return self.projects.get((owner_id, project_id))

    def update_project(self, owner_id: str, project_id: str, name: str) -> ProjectRow | None:
        old = self.projects.get((owner_id, project_id))
        if old is None:
            return None
        new = replace(old, name=name)
        self.projects[(owner_id, project_id)] = new
        return new

    def delete_project(self, owner_id: str, project_id: str) -> bool:
        return self.projects.pop((owner_id, project_id), None) is not None

    def insert_scan_job(self, **kwargs: Any) -> ScanJobRow:
        row = ScanJobRow(
            id=kwargs["job_id"],
            owner_id=kwargs["owner_id"],
            project_id=kwargs["project_id"],
            kind=kwargs["kind"],
            status="queued",
            target_kind=kwargs["target_kind"],
            source_bucket=kwargs["source_bucket"],
            source_key=kwargs["source_key"],
            source_sha256=kwargs["source_sha256"],
            source_bytes=kwargs["source_bytes"],
            scan_profile=kwargs["scan_profile"],
            phases=[],
            error=None,
            attempts=0,
            created_at=utc_now(),
            started_at=None,
            completed_at=None,
        )
        self.jobs.append(row)
        return row

    def get_job(self, owner_id: str, job_id: str) -> ScanJobRow | None:
        for row in self.jobs:
            if row.id == job_id and row.owner_id == owner_id:
                return row
        return None

    def list_jobs(
        self, owner_id: str, *, status: str | None = None, limit: int = 20
    ) -> list[ScanJobRow]:
        rows = [
            r
            for r in self.jobs
            if r.owner_id == owner_id and (status is None or r.status == status)
        ]
        return sorted(rows, key=lambda r: r.created_at, reverse=True)[:limit]

    def count_jobs(self, owner_id: str, statuses: Any) -> int:
        return sum(1 for r in self.jobs if r.owner_id == owner_id and r.status in statuses)

    def count_jobs_today(self, owner_id: str) -> int:
        today = utc_now().date()
        return sum(1 for r in self.jobs if r.owner_id == owner_id and r.created_at.date() == today)

    def cancel_queued_job(self, owner_id: str, job_id: str) -> bool:
        for index, row in enumerate(self.jobs):
            if row.id == job_id and row.owner_id == owner_id and row.status == "queued":
                self.jobs[index] = replace(row, status="cancelled", completed_at=utc_now())
                return True
        return False

    def get_quota(self, user_id: str) -> QuotaRow | None:
        return self.quotas.get(user_id)

    def get_report(self, owner_id: str, report_id: str) -> ReportRow | None:
        return self.reports.get((owner_id, report_id))

    def list_reports(
        self, owner_id: str, *, project_id: str | None = None, limit: int = 20
    ) -> list[ReportRow]:
        rows = [
            r
            for (o, _), r in self.reports.items()
            if o == owner_id and (project_id is None or r.project_id == project_id)
        ]
        return sorted(rows, key=lambda r: r.created_at, reverse=True)[:limit]


class RecordingStorage:
    """Signed-URL and object-download double; records every call."""

    def __init__(self, upload_bucket: str = "scan-uploads") -> None:
        self.upload_bucket = upload_bucket
        self.export_bucket = "report-exports"
        self.requests: list[tuple[str, str, int]] = []
        self.payloads: dict[str, bytes] = {}
        self.download_calls: list[tuple[str, str]] = []
        self.outage = False
        self.missing_keys: set[str] = set()
        self.oversize_key: str | None = None

    def signed_upload_url(self, owner_id: str, job_id: str, expires_in: int) -> tuple[str, str]:
        path = f"{owner_id}/{job_id}/source.zip"
        self.requests.append(("upload", path, expires_in))
        url = f"https://storage.example.test/object/sign/{path}?token=upload-{len(self.requests)}"
        return url, path

    def signed_download_url(self, bucket: str, key: str, expires_in: int) -> str:
        self.requests.append((bucket, key, expires_in))
        return f"https://storage.example.test/object/sign/{bucket}/{key}?token=dl"

    def download_to_file(self, bucket: str, key: str, destination: Path, max_bytes: int) -> int:
        from mugiwara.cloud.storage import UPLOAD_PATH_PATTERN, ObjectTooLargeError, StorageError

        if UPLOAD_PATH_PATTERN.match(key) is None:
            raise StorageError("object key does not match the upload layout")
        self.download_calls.append((bucket, key))
        if self.outage:
            raise StorageError("storage service unreachable")
        if key in self.missing_keys:
            raise StorageError("object not available (status 404)")
        payload = self.payloads.get(key)
        if payload is None:
            raise StorageError("object not available (status 404)")
        if self.oversize_key == key or len(payload) > max_bytes:
            raise ObjectTooLargeError("object exceeds the configured size limit")
        destination.write_bytes(payload)
        return len(payload)


class InMemoryWorkerDatabase:
    """Queue-side double implementing the WorkerDatabase protocol."""

    def __init__(self) -> None:
        from datetime import UTC, datetime

        self.jobs: list[ScanJobRow] = []
        self.reports: dict[tuple[str, str], ReportRow] = {}
        self.phase_updates: list[tuple[str, list[str]]] = []
        self.errors: dict[str, str] = {}
        self._lock = threading.Lock()
        self._clock = {"now": datetime.now(tz=UTC)}

    def add_job(self, **overrides: Any) -> ScanJobRow:
        job_id = overrides.pop("job_id", str(_uuid.uuid4()))
        owner = overrides.pop("owner_id", USER_A)
        values: dict[str, Any] = {
            "id": job_id,
            "owner_id": owner,
            "project_id": None,
            "kind": "scan",
            "status": "queued",
            "target_kind": "zip",
            "source_bucket": "scan-uploads",
            "source_key": f"{owner}/{job_id}/source.zip",
            "source_sha256": None,
            "source_bytes": None,
            "scan_profile": "standard",
        }
        values: dict[str, Any] = {
            "id": job_id,
            "owner_id": owner,
            "project_id": None,
            "kind": "scan",
            "status": "queued",
            "target_kind": "zip",
            "source_bucket": "scan-uploads",
            "source_key": f"{owner}/{job_id}/source.zip",
            "source_sha256": None,
            "source_bytes": None,
            "scan_profile": "standard",
            "phases": [],
            "error": None,
            "attempts": 0,
            "created_at": self._clock["now"],
            "started_at": None,
            "completed_at": None,
            "worker_id": None,
            "worker_lease_until": None,
        }
        values.update(overrides)
        row = ScanJobRow(**values)
        self.jobs.append(row)
        return row

    def _find(self, job_id: str) -> ScanJobRow | None:
        return next((r for r in self.jobs if r.id == job_id), None)

    def advance_clock(self, seconds: float) -> None:
        """Simulate wall-clock progress so leases can expire."""
        from datetime import timedelta

        self._clock["now"] += timedelta(seconds=seconds)

    def claim_next_scan_job(
        self, *, worker_id: str, lease_seconds: int, max_attempts: int
    ) -> ScanJobRow | None:
        with self._lock:
            candidates = [
                r
                for r in sorted(self.jobs, key=lambda r: r.created_at)
                if r.status == "queued" and r.kind == "scan" and r.attempts < max_attempts
            ]
            if not candidates:
                return None
            victim = replace(
                candidates[0],
                status="running",
                worker_id=worker_id,
                attempts=candidates[0].attempts + 1,
                error=None,
                worker_lease_until=self._clock["now"] + timedelta(seconds=lease_seconds),
            )
            self.jobs[self.jobs.index(candidates[0])] = victim
            return victim

    def update_job_phases(self, job_id: str, phases: list[str]) -> bool:
        row = self._find(job_id)
        if row is None or row.status != "running":
            return False
        self.phase_updates.append((job_id, list(phases)))
        self.jobs[self.jobs.index(row)] = replace(row, phases=list(phases))
        return True

    def complete_job(self, job_id: str) -> bool:
        row = self._find(job_id)
        if row is None or row.status != "running":
            return False
        self.jobs[self.jobs.index(row)] = replace(
            row,
            status="completed",
            completed_at=self._clock["now"],
            worker_lease_until=None,
        )
        return True

    def fail_job(self, job_id: str, error: str, *, retry: bool) -> str | None:
        row = self._find(job_id)
        if row is None:
            return None
        if retry and row.status != "running":
            return None
        if not retry and row.status not in ("running", "queued"):
            return None
        new_status = "queued" if retry else "failed"
        self.errors[job_id] = error
        self.jobs[self.jobs.index(row)] = replace(
            row,
            status=new_status,
            error=error,
            worker_id=None,
            worker_lease_until=None,
            completed_at=self._clock["now"] if not retry else None,
        )
        return new_status

    def recover_expired_leases(self, *, max_attempts: int) -> list[str]:
        now = self._clock["now"]
        recovered: list[str] = []
        for index, row in enumerate(self.jobs):
            lease = row.worker_lease_until
            if row.status == "running" and lease is not None and lease < now:
                exhausted = row.attempts >= max_attempts
                recovered.append(row.id)
                self.jobs[index] = replace(
                    row,
                    status="failed" if exhausted else "queued",
                    error=row.error
                    or ("lease expired after repeated crashes" if exhausted else None),
                    completed_at=self._clock["now"] if exhausted else None,
                    worker_id=None,
                    worker_lease_until=None,
                    started_at=None,
                )
        return recovered

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
    ) -> bool:
        report_id = str(envelope["report_id"])
        key = (owner_id, report_id)
        if key in self.reports:
            return False
        self.reports[key] = ReportRow(
            report_id=report_id,
            owner_id=owner_id,
            project_id=project_id,
            origin=origin,
            target_label=target_label,
            summary=dict(summary),
            envelope=dict(envelope),
            created_at=self._clock["now"],
        )
        return True


class AppHarness:
    def __init__(
        self,
        *,
        database: InMemoryDatabase | None = None,
        storage: RecordingStorage | None = None,
        verifier: SupabaseTokenVerifier | None = None,
        settings: CloudSettings | None = None,
    ) -> None:
        self.database = database or InMemoryDatabase()
        self.storage = storage or RecordingStorage()
        self.settings = settings or default_settings()
        self.jwks = RotatingJwks()
        if verifier is None:
            clock = {"now": 1_000_000.0}

            def fake_clock() -> float:
                return clock["now"]

            self.clock = clock
            cache = JwksCache(
                JWKS_URL,
                ttl_seconds=600,
                min_refresh_seconds=0,
                fetch=self.jwks.fetch,
                clock=fake_clock,
            )
            verifier = SupabaseTokenVerifier(
                cache, issuer=ISSUER, audience=AUDIENCE, leeway_seconds=0
            )
        self.verifier = verifier
        self.app = create_app(
            settings=self.settings,
            database=self.database,
            storage=self.storage,
            verifier=self.verifier,
        )
        self.client = TestClient(self.app, raise_server_exceptions=False)


def default_settings() -> CloudSettings:
    return CloudSettings(
        supabase_url="https://auth.example.test",
        supabase_anon_key=SecretStr("anon-value"),
        supabase_service_role_key=SecretStr(SERVICE_KEY_VALUE),
        database_url=SecretStr("postgresql://localhost/mugiwara_test"),
        upload_bucket="scan-uploads",
        export_bucket="report-exports",
        jwt_audience=AUDIENCE,
        jwt_leeway_seconds=0,
    )


def build_envelope_document(
    *,
    report_id: str | None = None,
    moment: datetime | None = None,
) -> dict[str, Any]:
    """Build a genuine ``mugiwara.scan-report`` envelope document."""
    from datetime import UTC as _UTC

    from mugiwara.models.finding import (
        Finding,
        FindingStatus,
        Severity,
        SourceLocation,
        VulnerabilityCategory,
    )
    from mugiwara.models.report import ScanReport
    from mugiwara.reports.store import (
        SCHEMA_VERSION,
        ScanConfigurationSnapshot,
        StoredScanReport,
        TargetMetadata,
        generate_report_id,
    )

    finding = Finding(
        title="SQL injection in user lookup",
        description="Untrusted username reaches cursor.execute.",
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        status=FindingStatus.VERIFIED,
        location=SourceLocation(file_path="app/db.py", start_line=10, end_line=12),
    )
    scan = ScanReport(target_path="demo.zip", scan_profile="standard", findings=[finding])
    envelope = StoredScanReport(
        schema_name="mugiwara.scan-report",
        schema_version=SCHEMA_VERSION,
        report_id=report_id or generate_report_id(),
        created_at=moment or datetime(2026, 8, 24, 12, 0, 0, tzinfo=_UTC),
        target=TargetMetadata(
            path="demo.zip",
            origin="archive: demo.zip",
            files_collected=3,
            secret_markers_found=0,
        ),
        configuration=ScanConfigurationSnapshot(
            scan_profile="standard",
            llm_provider="mock",
            llm_model="mock-analyst",
            sandbox_mode="subprocess",
            verification_enabled=True,
            include_evidence=True,
        ),
        scan=scan,
    )
    document: dict[str, Any] = dict(envelope.model_dump(mode="json", by_alias=True))
    return document


def auth_header(sub: str = USER_A) -> dict[str, str]:
    return {"Authorization": f"Bearer {make_token(sub=sub)}"}
