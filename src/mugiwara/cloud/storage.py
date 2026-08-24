"""Supabase Storage access: server-derived keys and signed URLs.

Rules enforced here:
- Object keys are always derived from the authenticated user id plus a
  server-generated job id; browsers never supply a storage path that is used
  verbatim.
- The upload bucket stays private; only time-limited signed URLs are handed
  out, minted with the service-role key strictly inside this module.
- Service credentials are ``SecretStr`` values and never logged or embedded
  into returned payloads beyond the Supabase-signed URL itself.
"""

import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from pydantic import SecretStr

SOURCE_FILENAME = "source.zip"

_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
UPLOAD_PATH_PATTERN = re.compile(
    rf"^(?P<owner>{_UUID})/(?P<job>{_UUID})/{re.escape(SOURCE_FILENAME)}$"
)

PostFn = Callable[
    [str, Mapping[str, str], Mapping[str, Any], float],
    tuple[int, Mapping[str, Any]],
]
StreamGetFn = Callable[[str, Mapping[str, str], Path, int], int]


class StorageError(Exception):
    """Signed URL or object transfer could not be completed."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class ObjectTooLargeError(StorageError):
    """Download exceeded the configured byte cap; treated as permanent."""


def upload_key(owner_id: str, job_id: str) -> str:
    """Canonical object key for a user's uploaded source archive."""
    return f"{owner_id}/{job_id}/{SOURCE_FILENAME}"


def canonical_upload_path(owner_id: str, candidate: str) -> str:
    """Validate a client-supplied path against the caller's own namespace.

    A path is acceptable only if it matches the exact shape the server mints
    for THIS user (``<their uid>/<uuid>/source.zip``). Anything else - other
    users' prefixes, traversal segments, foreign file names - is rejected.

    Raises:
        ValueError: If the path does not belong to the calling user's namespace.
    """
    match = UPLOAD_PATH_PATTERN.match(candidate)
    if match is None or match.group("owner") != owner_id:
        msg = "upload path must use the server-issued layout for your account"
        raise ValueError(msg)
    return candidate


class SupabaseStorage:
    """Issues signed URLs through the Supabase Storage REST API."""

    def __init__(
        self,
        *,
        base_url: str,
        service_key: SecretStr,
        upload_bucket: str,
        export_bucket: str,
        post: PostFn | None = None,
        stream_get: StreamGetFn | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._service_key = service_key
        self._upload_bucket = upload_bucket
        self._export_bucket = export_bucket
        self._post: PostFn = post or self._httpx_post
        self._stream_get: StreamGetFn | None = stream_get
        self._timeout = timeout_seconds

    @property
    def upload_bucket(self) -> str:
        return self._upload_bucket

    @property
    def export_bucket(self) -> str:
        return self._export_bucket

    def signed_upload_url(self, owner_id: str, job_id: str, expires_in: int) -> tuple[str, str]:
        path = upload_key(owner_id, job_id)
        url = self._sign(self._upload_bucket, path, expires_in)
        return url, path

    def signed_download_url(self, bucket: str, key: str, expires_in: int) -> str:
        return self._sign(bucket, key, expires_in)

    def download_to_file(self, bucket: str, key: str, destination: Path, max_bytes: int) -> int:
        """Stream one private object to ``destination`` under a hard size cap.

        The key must match the canonical upload layout; this is defense in
        depth on top of the worker's own ownership validation.

        Returns:
            Number of bytes written.
        """
        if UPLOAD_PATH_PATTERN.match(key) is None:
            raise StorageError("object key does not match the upload layout")
        getter = self._stream_get or self._httpx_stream_get
        try:
            return getter(
                f"{self._base}/storage/v1/object/{bucket}/{key}",
                {"Authorization": f"Bearer {self._service_key.get_secret_value()}"},
                destination,
                max_bytes,
            )
        except StorageError:
            destination.unlink(missing_ok=True)
            raise
        except OSError as exc:
            destination.unlink(missing_ok=True)
            raise StorageError("local scratch write failed") from exc

    def _httpx_stream_get(
        self, url: str, headers: Mapping[str, str], destination: Path, max_bytes: int
    ) -> int:
        import httpx

        try:
            with httpx.stream("GET", url, headers=dict(headers), timeout=self._timeout) as response:
                if response.status_code in (400, 404):
                    raise StorageError(f"object not available (status {response.status_code})")
                if not 200 <= response.status_code < 300:
                    raise StorageError(f"object download failed (status {response.status_code})")
                written = 0
                with open(destination, "wb") as handle:
                    for chunk in response.iter_bytes():
                        written += len(chunk)
                        if written > max_bytes:
                            handle.close()
                            raise ObjectTooLargeError("object exceeds the configured size limit")
                        handle.write(chunk)
                return written
        except httpx.HTTPError as exc:
            raise StorageError("storage service unreachable") from exc

    def _sign(self, bucket: str, key: str, expires_in: int) -> str:
        endpoint = f"{self._base}/storage/v1/object/sign/{bucket}/{key}"
        status, body = self._post(
            endpoint,
            {"Authorization": f"Bearer {self._service_key.get_secret_value()}"},
            {"expiresIn": expires_in},
            self._timeout,
        )
        signed_path = None
        if 200 <= status < 300 and isinstance(body, dict):
            value = body.get("signedURL") or body.get("signedUrl")
            if isinstance(value, str):
                signed_path = value
        if signed_path is None:
            raise StorageError(f"storage refused to sign object (status {status})")
        return f"{self._base}/storage/v1{signed_path}"

    @staticmethod
    def _httpx_post(
        url: str, headers: Mapping[str, str], payload: Mapping[str, Any], timeout: float
    ) -> tuple[int, Mapping[str, Any]]:
        import httpx

        try:
            response = httpx.post(url, headers=dict(headers), json=dict(payload), timeout=timeout)
        except httpx.HTTPError as exc:
            raise StorageError("storage service unreachable") from exc
        try:
            body: Any = response.json()
        except ValueError:
            body = {}
        if not isinstance(body, dict):
            body = {}
        return response.status_code, body
