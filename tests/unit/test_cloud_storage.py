"""Unit tests for Supabase Storage signing and download logic.

These tests verify that upload signed URLs use the correct Supabase Storage
REST endpoint (/storage/v1/object/upload/sign/) while download signed URLs
use the read endpoint (/storage/v1/object/sign/).  The real httpx transport
is replaced with a mock post function so no network calls are made.
"""

from collections.abc import Mapping
from typing import Any
from unittest.mock import MagicMock

import pytest

from mugiwara.cloud.storage import StorageError, SupabaseStorage, upload_key

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FAKE_KEY = "secret-service-role-key"


def _make_storage() -> SupabaseStorage:
    return SupabaseStorage(
        base_url="https://project.supabase.co",
        service_key=MagicMock(get_secret_value=lambda: FAKE_KEY),
        upload_bucket="scan-uploads",
        export_bucket="report-exports",
        timeout_seconds=5.0,
    )


class FakePost:
    """Records the last POST call and returns a controllable response."""

    def __init__(self, status: int, body: dict[str, Any]) -> None:
        self._status = status
        self._body = body
        self.calls: list[tuple[str, Mapping[str, str], Mapping[str, Any], float]] = []

    def __call__(
        self,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, Any],
        timeout: float,
    ) -> tuple[int, Mapping[str, Any]]:
        self.calls.append((url, headers, payload, timeout))
        return self._status, self._body


# ---------------------------------------------------------------------------
# Upload signing
# ---------------------------------------------------------------------------


class TestSignUpload:
    def test_uses_upload_sign_endpoint(self) -> None:
        """Upload signing must call /storage/v1/object/upload/sign/{bucket}/{key}."""
        fake_url = "/object/upload/sign/scan-uploads/abc/def/source.zip?token=tok123"
        post = FakePost(200, {"url": fake_url, "token": "tok123", "path": "..."})
        storage = _make_storage()
        storage._post = post

        result_url, path = storage.signed_upload_url("abc", "def", expires_in=900)

        assert len(post.calls) == 1
        endpoint = post.calls[0][0]
        assert "/object/upload/sign/" in endpoint
        assert "/object/sign/" not in endpoint or "/upload/sign/" in endpoint
        assert result_url.endswith(fake_url)
        assert path == upload_key("abc", "def")

    def test_url_response_parsed_from_url_field(self) -> None:
        """The upload endpoint returns {url: ..., token: ..., path: ...}."""
        fake_url = "/object/upload/sign/scan-uploads/u/j/source.zip?token=abc"
        post = FakePost(200, {"url": fake_url, "token": "abc", "path": "u/j/source.zip"})
        storage = _make_storage()
        storage._post = post

        result_url, _ = storage.signed_upload_url("u", "j", expires_in=600)

        assert "https://project.supabase.co/storage/v1" in result_url

    def test_raises_on_non_200(self) -> None:
        post = FakePost(400, {"message": "bucket not found"})
        storage = _make_storage()
        storage._post = post

        with pytest.raises(StorageError, match="refused to sign upload URL"):
            storage.signed_upload_url("u", "j", expires_in=600)

    def test_raises_when_url_field_missing(self) -> None:
        """If Supabase returns 200 but no 'url' field, we raise."""
        post = FakePost(200, {"signedURL": "/wrong-key"})
        storage = _make_storage()
        storage._post = post

        with pytest.raises(StorageError, match="refused to sign upload URL"):
            storage.signed_upload_url("u", "j", expires_in=600)


# ---------------------------------------------------------------------------
# Download signing
# ---------------------------------------------------------------------------


class TestSignDownload:
    def test_uses_download_sign_endpoint(self) -> None:
        """Download signing must call /storage/v1/object/sign/{bucket}/{key}."""
        fake_url = "/object/sign/scan-uploads/abc/def/source.zip?token=dl123"
        post = FakePost(200, {"signedURL": fake_url})
        storage = _make_storage()
        storage._post = post

        result_url = storage.signed_download_url("scan-uploads", "abc/def/source.zip", 300)

        assert len(post.calls) == 1
        endpoint = post.calls[0][0]
        assert "/object/sign/" in endpoint
        assert "/object/upload/sign/" not in endpoint
        assert result_url.endswith(fake_url)

    def test_raises_on_non_200(self) -> None:
        post = FakePost(400, {"message": "not found"})
        storage = _make_storage()
        storage._post = post

        with pytest.raises(StorageError, match="refused to sign object"):
            storage.signed_download_url("scan-uploads", "a/b/source.zip", 300)

    def test_raises_when_signed_url_field_missing(self) -> None:
        post = FakePost(200, {"url": "/wrong-key"})
        storage = _make_storage()
        storage._post = post

        with pytest.raises(StorageError, match="refused to sign object"):
            storage.signed_download_url("scan-uploads", "a/b/source.zip", 300)


# ---------------------------------------------------------------------------
# Upload key construction
# ---------------------------------------------------------------------------


class TestUploadKey:
    def test_format(self) -> None:
        assert upload_key("owner-123", "job-456") == "owner-123/job-456/source.zip"
