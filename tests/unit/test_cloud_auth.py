"""Authentication tests for the cloud API (Supabase JWT + JWKS).

Covers the mandatory matrix: invalid, expired, wrong-signature, wrong-audience
and wrong-issuer tokens are rejected; the authenticated user is resolved from
the verified subject; protected endpoints reject unauthenticated calls; and no
service-role material ever reaches a response or generated schema.
"""

import pytest

from mugiwara.cloud.auth import JwksCache
from tests.unit.cloud_support import (
    AUDIENCE,
    ISSUER,
    JWKS_URL,
    SERVICE_KEY_VALUE,
    USER_A,
    USER_B,
    AppHarness,
    RotatingJwks,
    auth_header,
    make_token,
    primary_key,
    rogue_key,
)

PROTECTED_ROUTES = [
    ("GET", "/api/me", None),
    ("GET", "/api/projects", None),
    ("POST", "/api/projects", {"name": "x"}),
    ("PATCH", "/api/projects/abc", {"name": "x"}),
    ("DELETE", "/api/projects/abc", None),
    ("POST", "/api/uploads/sign", None),
    ("POST", "/api/jobs", {"upload_path": "x/y/source.zip"}),
    ("GET", "/api/jobs", None),
    ("POST", "/api/jobs/abc/cancel", None),
    ("GET", "/api/jobs/abc/source-url", None),
    ("GET", "/api/reports", None),
    ("GET", "/api/reports/abc/export", None),
    ("GET", "/api/quota", None),
]


@pytest.fixture()
def harness() -> AppHarness:
    return AppHarness()


def _me(harness: AppHarness, token: str) -> dict[str, object]:
    response = harness.client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
    return {"status": response.status_code, "body": response.json()}


# -- positive path ----------------------------------------------------------


def test_valid_token_authenticates_subject(harness: AppHarness) -> None:
    result = _me(harness, make_token(sub=USER_A))
    assert result["status"] == 200
    body = result["body"]
    assert isinstance(body, dict)
    assert body["user_id"] == USER_A
    assert body["email"].endswith("@example.test")


def test_second_user_gets_their_own_identity(harness: AppHarness) -> None:
    result = _me(harness, make_token(sub=USER_B))
    body = result["body"]
    assert isinstance(body, dict)
    assert body["user_id"] == USER_B


# -- rejection matrix -------------------------------------------------------


def test_garbage_token_rejected(harness: AppHarness) -> None:
    result = _me(harness, "not-a-jwt")
    assert result["status"] == 401


def test_expired_token_rejected(harness: AppHarness) -> None:
    token = make_token(claims={"exp": 1_000_000})
    result = _me(harness, token)
    assert result["status"] == 401


def test_wrong_signature_rejected(harness: AppHarness) -> None:
    rogue_pem, _ = rogue_key()
    token = make_token(signing_pem=rogue_pem, kid="kid-1")
    result = _me(harness, token)
    assert result["status"] == 401


def test_unknown_kid_rejected(harness: AppHarness) -> None:
    primary_pem, _ = primary_key()
    token = make_token(signing_pem=primary_pem, kid="kid-rotated-away")
    result = _me(harness, token)
    assert result["status"] == 401


def test_hs256_algorithm_confusion_rejected(harness: AppHarness) -> None:
    token = make_token(algorithm="HS256")
    result = _me(harness, token)
    assert result["status"] == 401


def test_wrong_audience_rejected(harness: AppHarness) -> None:
    token = make_token(claims={"aud": ["some-other-app"]})
    result = _me(harness, token)
    assert result["status"] == 401


def test_missing_audience_rejected(harness: AppHarness) -> None:
    token = make_token(claims={"aud": None})
    result = _me(harness, token)
    assert result["status"] == 401


def test_wrong_issuer_rejected(harness: AppHarness) -> None:
    token = make_token(claims={"iss": "https://evil.example.test/auth/v1"})
    result = _me(harness, token)
    assert result["status"] == 401


def test_missing_subject_rejected(harness: AppHarness) -> None:
    token = make_token(claims={"sub": None})
    result = _me(harness, token)
    assert result["status"] == 401


def test_non_uuid_subject_rejected(harness: AppHarness) -> None:
    token = make_token(sub="not-a-uuid")
    result = _me(harness, token)
    assert result["status"] == 401


# -- transport-level auth enforcement ----------------------------------------


@pytest.mark.parametrize(("method", "path", "payload"), PROTECTED_ROUTES)
def test_protected_routes_require_bearer_token(
    harness: AppHarness, method: str, path: str, payload: dict[str, str] | None
) -> None:
    response = harness.client.request(method, path, json=payload)
    assert response.status_code == 401


def test_authorization_without_bearer_prefix_rejected(harness: AppHarness) -> None:
    token = make_token()
    response = harness.client.get("/api/me", headers={"Authorization": f"Token {token}"})
    assert response.status_code == 401


def test_health_is_public_and_minimal(harness: AppHarness) -> None:
    response = harness.client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "mugiwara-cloud-api"}


# -- JWKS cache behavior ------------------------------------------------------


def test_jwks_refreshes_once_for_rotated_key(harness: AppHarness) -> None:
    rogue_pem, rogue_jwk = rogue_key()
    harness.jwks.published.append(dict(rogue_jwk, kid="kid-2"))
    before = harness.jwks.calls

    stale = make_token(kid="kid-missing")
    assert (
        harness.client.get("/api/me", headers={"Authorization": f"Bearer {stale}"}).status_code
        == 401
    )

    good = make_token(kid="kid-2", signing_pem=rogue_pem)
    response = harness.client.get("/api/me", headers={"Authorization": f"Bearer {good}"})
    assert response.status_code == 200
    assert harness.jwks.calls >= before + 1


def test_jwks_ttl_expiry_triggers_refetch(harness: AppHarness) -> None:
    token = make_token()
    first = harness.client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
    assert first.status_code == 200
    calls_after_first = harness.jwks.calls
    harness.clock["now"] += 601
    second = harness.client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
    assert second.status_code == 200
    assert harness.jwks.calls == calls_after_first + 1


def test_jwks_fetch_failure_yields_503(harness: AppHarness) -> None:
    harness.clock["now"] += 10_000
    harness.jwks.fail_next = True
    harness.jwks.published = []
    token = make_token()
    response = harness.client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 503


def test_jwks_fetch_failure_keeps_existing_cache(harness: AppHarness) -> None:
    token = make_token()
    first = harness.client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
    assert first.status_code == 200
    harness.clock["now"] += 10_000
    harness.jwks.fail_next = True
    again = harness.client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
    assert again.status_code == 200


def test_jwks_cache_direct_unknown_kid_is_rate_limited() -> None:
    jwks = RotatingJwks()
    clock = {"now": 0.0}
    cache = JwksCache(
        JWKS_URL,
        ttl_seconds=600,
        min_refresh_seconds=300,
        fetch=jwks.fetch,
        clock=lambda: clock["now"],
    )
    from mugiwara.cloud.auth import TokenInvalidError

    for _ in range(3):
        with pytest.raises(TokenInvalidError):
            cache.get_key("garbage-kid")
    assert jwks.calls == 1
    clock["now"] += 301
    with pytest.raises(TokenInvalidError):
        cache.get_key("garbage-kid")
    assert jwks.calls == 2


# -- secret hygiene ------------------------------------------------------------


def test_service_role_secret_never_appears_in_responses_or_schema(
    harness: AppHarness,
) -> None:
    client = harness.client
    captured: list[object] = []

    def record(response: object) -> object:
        captured.append(response)
        return response

    ok = client.get("/health")
    record(ok)
    me = client.get("/api/me", headers=auth_header(USER_A))
    record(me)
    project = client.post("/api/projects", json={"name": "p"}, headers=auth_header(USER_A))
    record(project)
    bad_body = client.post(
        "/api/projects",
        json={"name": "p", "owner_id": USER_B},
        headers=auth_header(USER_A),
    )
    record(bad_body)

    settings_repr = repr(harness.settings)
    assert SERVICE_KEY_VALUE not in settings_repr
    assert str(harness.settings.supabase_service_role_key) != SERVICE_KEY_VALUE

    schema = harness.app.openapi()
    assert SERVICE_KEY_VALUE not in str(schema)

    for response in captured:
        http_response = response
        assert SERVICE_KEY_VALUE not in str(getattr(http_response, "content", b""))
        assert SERVICE_KEY_VALUE not in str(dict(getattr(http_response, "headers", {})))


def test_responses_never_echo_authorization_header(harness: AppHarness) -> None:
    header = auth_header(USER_A)
    responses = [
        harness.client.get("/api/me", headers=header),
        harness.client.post("/api/projects", json={"name": "p"}, headers=header),
        harness.client.get("/api/nope", headers=header),
        harness.client.get("/api/me"),
    ]
    for response in responses:
        assert "authorization" not in {k.lower() for k in response.headers}
        assert header["Authorization"].split(".", 1)[0][:20] not in response.text


def test_issuer_and_audience_configured_values_are_used(harness: AppHarness) -> None:
    assert harness.settings.jwt_audience == AUDIENCE
    assert ISSUER in JWKS_URL
