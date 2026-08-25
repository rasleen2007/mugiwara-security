"""Authorization and IDOR tests for the cloud API.

Every test proves that ownership decisions flow exclusively from the verified
JWT subject: cross-user reads/writes return 404, client-supplied authority
fields are rejected, storage paths outside the caller's namespace are refused,
quotas gate submission, and only queued jobs can be cancelled.
"""

import re
import uuid as _uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from mugiwara.cloud.db import DEFAULT_QUOTA, QuotaRow, ReportRow
from tests.unit.cloud_support import (
    SERVICE_KEY_VALUE,
    USER_A,
    USER_B,
    AppHarness,
    auth_header,
)


@pytest.fixture()
def harness() -> AppHarness:
    return AppHarness()


def _seed_b_resources(harness: AppHarness) -> dict[str, str]:
    project = harness.database.create_project(USER_B, "b-project")
    job = harness.database.add_job(owner_id=USER_B, project_id=project.id)
    report_id = "20260824T101112-" + _uuid.uuid4().hex[:10]
    harness.database.put_report(
        ReportRow(
            report_id=report_id,
            owner_id=USER_B,
            project_id=project.id,
            origin="archive",
            target_label="demo.zip",
            summary={"total_findings": 1},
            envelope={},
            created_at=job.created_at,
        )
    )
    return {"project": project.id, "job": job.id, "report": report_id}


# -- identity ---------------------------------------------------------------


def test_me_returns_verified_identity_only(harness: AppHarness) -> None:
    response = harness.client.get("/api/me", headers=auth_header(USER_A))
    body = response.json()
    assert response.status_code == 200
    assert body == {
        "user_id": USER_A,
        "email": f"{USER_A[:2]}@example.test",
        "role": "authenticated",
    }


def test_owner_id_in_token_cannot_be_rebound_via_url_or_query(
    harness: AppHarness,
) -> None:
    seeded = _seed_b_resources(harness)
    for path in (
        f"/api/jobs/{seeded['job']}?owner_id={USER_A}",
        f"/api/reports/{seeded['report']}?owner_id={USER_A}",
        f"/api/projects/{seeded['project']}?user_id={USER_A}",
    ):
        response = harness.client.get(path, headers=auth_header(USER_A))
        assert response.status_code == 404


# -- spoofed authority fields in bodies ---------------------------------------


def test_spoofed_project_fields_rejected(harness: AppHarness) -> None:
    for extra in ({"owner_id": USER_B}, {"user_id": USER_B}, {"id": "controlled"}):
        response = harness.client.post(
            "/api/projects", json={"name": "x", **extra}, headers=auth_header(USER_A)
        )
        assert response.status_code == 422, f"{extra} must be rejected"


def test_spoofed_job_fields_rejected(harness: AppHarness) -> None:
    path = f"{USER_A}/{_uuid.uuid4()}/source.zip"
    base: dict[str, Any] = {"upload_path": path}
    for extra in (
        {"owner_id": USER_B},
        {"user_id": USER_B},
        {"status": "completed"},
        {"job_id": "fixed-id"},
        {"source_key": f"{USER_B}/evil/source.zip"},
    ):
        response = harness.client.post(
            "/api/jobs", json={**base, **extra}, headers=auth_header(USER_A)
        )
        assert response.status_code == 422, f"{extra} must be rejected"


def test_created_job_row_is_owned_by_verified_subject(harness: AppHarness) -> None:
    path = f"{USER_A}/{_uuid.uuid4()}/source.zip"
    response = harness.client.post(
        "/api/jobs", json={"upload_path": path}, headers=auth_header(USER_A)
    )
    assert response.status_code == 201
    job = response.json()
    row = next(r for r in harness.database.jobs if r.id == job["id"])
    fetched = harness.database.get_job(USER_A, job["id"])
    assert row.owner_id == USER_A
    assert fetched is not None and fetched.owner_id == USER_A
    assert row.status == "queued"
    assert row.source_key.startswith(f"{USER_A}/")


# -- cross-user access (IDOR) --------------------------------------------------


def test_user_a_cannot_read_user_b_project(harness: AppHarness) -> None:
    seeded = _seed_b_resources(harness)
    response = harness.client.get(f"/api/projects/{seeded['project']}", headers=auth_header(USER_A))
    assert response.status_code == 404


def test_user_a_cannot_modify_or_delete_user_b_project(harness: AppHarness) -> None:
    seeded = _seed_b_resources(harness)
    renamed = harness.client.patch(
        f"/api/projects/{seeded['project']}",
        json={"name": "hijacked"},
        headers=auth_header(USER_A),
    )
    deleted = harness.client.delete(
        f"/api/projects/{seeded['project']}", headers=auth_header(USER_A)
    )
    assert renamed.status_code == 404
    assert deleted.status_code == 404
    assert harness.database.projects[(USER_B, seeded["project"])].name == "b-project"


def test_user_a_cannot_read_user_b_scan_job(harness: AppHarness) -> None:
    seeded = _seed_b_resources(harness)
    listing = harness.client.get("/api/jobs", headers=auth_header(USER_A))
    detail = harness.client.get(f"/api/jobs/{seeded['job']}", headers=auth_header(USER_A))
    assert detail.status_code == 404
    assert all(item["id"] != seeded["job"] for item in listing.json())


def test_user_a_cannot_cancel_user_b_queued_job(harness: AppHarness) -> None:
    seeded = _seed_b_resources(harness)
    response = harness.client.post(f"/api/jobs/{seeded['job']}/cancel", headers=auth_header(USER_A))
    assert response.status_code == 404
    victim = next(r for r in harness.database.jobs if r.id == seeded["job"])
    assert victim.status == "queued"


def test_user_a_cannot_read_or_export_user_b_report(harness: AppHarness) -> None:
    seeded = _seed_b_resources(harness)
    detail = harness.client.get(f"/api/reports/{seeded['report']}", headers=auth_header(USER_A))
    exported = harness.client.get(
        f"/api/reports/{seeded['report']}/export?format=json",
        headers=auth_header(USER_A),
    )
    listed = harness.client.get("/api/reports", headers=auth_header(USER_A))
    assert detail.status_code == 404
    assert exported.status_code == 404
    assert listed.json() == []


def test_user_a_cannot_create_job_under_user_b_project(harness: AppHarness) -> None:
    seeded = _seed_b_resources(harness)
    path = f"{USER_A}/{_uuid.uuid4()}/source.zip"
    response = harness.client.post(
        "/api/jobs",
        json={"upload_path": path, "project_id": seeded["project"]},
        headers=auth_header(USER_A),
    )
    assert response.status_code == 404


# -- storage path enforcement ---------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "../etc/passwd/source.zip",
        "random-key/source.zip",
        "source.zip",
        f"{USER_A}/source.zip",
        f"../../{USER_B}/{_uuid.uuid4().hex}/source.zip",
        f"{USER_B.upper()}/{_uuid.uuid4()}/source.zip",
        f"{USER_A}/{_uuid.uuid4()}/evil.exe",
    ],
)
def test_arbitrary_storage_paths_rejected(harness: AppHarness, path: str) -> None:
    response = harness.client.post(
        "/api/jobs", json={"upload_path": path}, headers=auth_header(USER_A)
    )
    assert response.status_code == 400
    stored_keys = [row.source_key for row in harness.database.jobs]
    assert stored_keys == []


def test_empty_upload_path_fails_validation(harness: AppHarness) -> None:
    response = harness.client.post(
        "/api/jobs", json={"upload_path": ""}, headers=auth_header(USER_A)
    )
    assert response.status_code == 422


def test_upload_sign_issues_caller_scoped_path(harness: AppHarness) -> None:
    response = harness.client.post("/api/uploads/sign", headers=auth_header(USER_A))
    body = response.json()
    assert response.status_code == 200
    pattern = rf"^{re.escape(USER_A)}/[0-9a-f-]{{36}}/source\.zip$"
    assert re.match(pattern, body["path"])
    assert body["upload_url"].startswith("https://storage.example.test/")
    assert harness.storage.requests[-1][:2] == ("upload", body["path"])
    assert SERVICE_KEY_VALUE not in str(body)


def test_source_download_url_uses_stored_server_derived_key(harness: AppHarness) -> None:
    path = f"{USER_A}/{_uuid.uuid4()}/source.zip"
    created = harness.client.post(
        "/api/jobs", json={"upload_path": path}, headers=auth_header(USER_A)
    ).json()
    before = len(harness.storage.requests)
    response = harness.client.get(
        f"/api/jobs/{created['id']}/source-url", headers=auth_header(USER_A)
    )
    assert response.status_code == 200
    assert response.json()["download_url"].startswith("https://storage.example.test/")
    bucket, key, ttl = harness.storage.requests[-1]
    assert key == path
    assert bucket == "scan-uploads"
    assert ttl > 0
    assert len(harness.storage.requests) == before + 1


# -- quota enforcement ------------------------------------------------------------


def test_queue_capacity_quota_enforced(harness: AppHarness) -> None:
    harness.database.set_quota(USER_A, QuotaRow(1, 0, DEFAULT_QUOTA.max_source_bytes, 100))
    ok = harness.client.post(
        "/api/jobs",
        json={"upload_path": f"{USER_A}/{_uuid.uuid4()}/source.zip"},
        headers=auth_header(USER_A),
    )
    assert ok.status_code == 201
    blocked = harness.client.post(
        "/api/jobs",
        json={"upload_path": f"{USER_A}/{_uuid.uuid4()}/source.zip"},
        headers=auth_header(USER_A),
    )
    assert blocked.status_code == 409


def test_daily_quota_enforced(harness: AppHarness) -> None:
    harness.database.set_quota(USER_A, QuotaRow(5, 5, DEFAULT_QUOTA.max_source_bytes, 1))
    first = harness.client.post(
        "/api/jobs",
        json={"upload_path": f"{USER_A}/{_uuid.uuid4()}/source.zip"},
        headers=auth_header(USER_A),
    )
    second = harness.client.post(
        "/api/jobs",
        json={"upload_path": f"{USER_A}/{_uuid.uuid4()}/source.zip"},
        headers=auth_header(USER_A),
    )
    assert first.status_code == 201
    assert second.status_code == 429


def test_source_size_cap_enforced(harness: AppHarness) -> None:
    tiny = QuotaRow(5, 5, 1024, 100)
    harness.database.set_quota(USER_A, tiny)
    response = harness.client.post(
        "/api/jobs",
        json={
            "upload_path": f"{USER_A}/{_uuid.uuid4()}/source.zip",
            "source_bytes": 2048,
        },
        headers=auth_header(USER_A),
    )
    assert response.status_code == 413


def test_quota_endpoint_reports_effective_defaults(harness: AppHarness) -> None:
    response = harness.client.get("/api/quota", headers=auth_header(USER_A))
    body = response.json()
    assert response.status_code == 200
    assert body["max_jobs_per_day"] == DEFAULT_QUOTA.max_jobs_per_day
    assert body["max_source_bytes"] == DEFAULT_QUOTA.max_source_bytes


# -- cancellation lifecycle ----------------------------------------------------------


def test_cancel_moves_queued_job_to_cancelled(harness: AppHarness) -> None:
    created = harness.client.post(
        "/api/jobs",
        json={"upload_path": f"{USER_A}/{_uuid.uuid4()}/source.zip"},
        headers=auth_header(USER_A),
    ).json()
    response = harness.client.post(f"/api/jobs/{created['id']}/cancel", headers=auth_header(USER_A))
    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"


def test_cancel_running_job_conflicts(harness: AppHarness) -> None:
    job = harness.database.add_job(owner_id=USER_A, status="running")
    response = harness.client.post(f"/api/jobs/{job.id}/cancel", headers=auth_header(USER_A))
    assert response.status_code == 409


def test_cancel_twice_conflicts(harness: AppHarness) -> None:
    created = harness.client.post(
        "/api/jobs",
        json={"upload_path": f"{USER_A}/{_uuid.uuid4()}/source.zip"},
        headers=auth_header(USER_A),
    ).json()
    first = harness.client.post(f"/api/jobs/{created['id']}/cancel", headers=auth_header(USER_A))
    second = harness.client.post(f"/api/jobs/{created['id']}/cancel", headers=auth_header(USER_A))
    assert first.status_code == 200
    assert second.status_code == 409


# -- report export happy paths --------------------------------------------------------


def _seed_readable_report(harness: AppHarness) -> str:
    from tests.unit.cloud_support import build_envelope_document

    document = build_envelope_document()
    report_id = str(document["report_id"])
    harness.database.put_report(
        ReportRow(
            report_id=report_id,
            owner_id=USER_A,
            project_id=None,
            origin="archive",
            target_label="demo.zip",
            summary=dict(document["scan"]["summary"]),  # type: ignore[arg-type]
            envelope=document,
            created_at=datetime(2026, 8, 24, 12, 0, 0, tzinfo=UTC),
        )
    )
    return report_id


_EXPORT_EXTENSIONS = {"markdown": "md", "sarif": "sarif", "json": "json"}


@pytest.mark.parametrize("fmt", ["markdown", "sarif", "json"])
def test_export_formats_render_for_owner(harness: AppHarness, fmt: str) -> None:
    report_id = _seed_readable_report(harness)
    response = harness.client.get(
        f"/api/reports/{report_id}/export?format={fmt}", headers=auth_header(USER_A)
    )
    assert response.status_code == 200
    disposition = response.headers["content-disposition"]
    assert f"{report_id}.{_EXPORT_EXTENSIONS[fmt]}" in disposition
    if fmt == "markdown":
        assert "Mugiwara" in response.text
    elif fmt == "sarif":
        payload = response.json()
        assert payload["version"] == "2.1.0"
    else:
        assert response.json()["schema"] == "mugiwara.scan-report"


def test_report_detail_returns_metadata_without_envelope(harness: AppHarness) -> None:
    report_id = _seed_readable_report(harness)
    response = harness.client.get(f"/api/reports/{report_id}", headers=auth_header(USER_A))
    body = response.json()
    assert response.status_code == 200
    assert body["report_id"] == report_id
    assert "envelope" not in body


# -- CORS enforcement ----------------------------------------------------------


def test_preflight_allowed_origin_returns_cors_headers(harness: AppHarness) -> None:
    response = harness.client.options(
        "/api/me",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code in (200, 405)
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert "GET" in response.headers.get("access-control-allow-methods", "")


def test_preflight_disallowed_origin_omits_cors_headers(harness: AppHarness) -> None:
    response = harness.client.options(
        "/api/me",
        headers={
            "Origin": "https://evil.example.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert "access-control-allow-origin" not in response.headers


def test_regular_request_includes_cors_headers_for_allowed_origin(harness: AppHarness) -> None:
    response = harness.client.get("/health", headers={"Origin": "http://localhost:3000"})
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert response.headers.get("access-control-allow-credentials") == "true"


def test_regular_request_omits_cors_headers_for_disallowed_origin(harness: AppHarness) -> None:
    response = harness.client.get("/health", headers={"Origin": "https://evil.example.com"})
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


def test_custom_cors_origins_from_settings() -> None:
    from mugiwara.cloud.config import CloudSettings
    from pydantic import SecretStr

    settings = CloudSettings(
        supabase_url="https://auth.example.test",
        supabase_anon_key=SecretStr("anon"),
        supabase_service_role_key=SecretStr("svc"),
        database_url=SecretStr("postgresql://localhost/test"),
        cors_origins=["https://app.example.com", "https://staging.example.com"],
    )
    assert settings.cors_origins == ["https://app.example.com", "https://staging.example.com"]


def test_cors_origins_parsed_from_comma_separated_string() -> None:
    from mugiwara.cloud.config import CloudSettings
    from pydantic import SecretStr

    settings = CloudSettings(
        supabase_url="https://auth.example.test",
        supabase_anon_key=SecretStr("anon"),
        supabase_service_role_key=SecretStr("svc"),
        database_url=SecretStr("postgresql://localhost/test"),
        cors_origins="https://a.com, https://b.com",
    )
    assert settings.cors_origins == ["https://a.com", "https://b.com"]


def test_cors_headers_sent_with_auth_error(harness: AppHarness) -> None:
    response = harness.client.get("/api/me", headers={"Origin": "http://localhost:3000"})
    assert response.status_code == 401
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"
