"""HTTP transport abstraction for LLM providers.

The transport is deliberately tiny and dependency-free (stdlib
``urllib.request``) so providers can talk to local model servers without
pulling an HTTP client library into the project.

Safety properties:

- Every request URL must live under the transport's pinned base URL (when
  one is configured); any other destination is refused before a socket is
  ever opened. Providers pin the explicitly configured local endpoint, which
  makes it impossible for prompt content or server responses to redirect
  requests elsewhere.
- Only ``http`` and ``https`` schemes are accepted.
- Timeouts are mandatory and come from configuration.
"""

import json
import urllib.error
import urllib.request
from typing import Any, Protocol

from mugiwara.core.exceptions import MugiwaraError


class TransportError(MugiwaraError):
    """Raised when an HTTP transport operation fails."""


class Transport(Protocol):
    """Minimal synchronous JSON-over-HTTP contract used by providers."""

    def post_json(
        self,
        url: str,
        payload: dict[str, Any],
        timeout_seconds: float,
    ) -> dict[str, Any]:
        """POST a JSON body and return the decoded JSON response object."""
        ...

    def get_json(self, url: str, timeout_seconds: float) -> dict[str, Any]:
        """GET a URL and return the decoded JSON response object."""
        ...


def validate_pinned_url(base_url: str, url: str) -> None:
    """Ensure ``url`` stays under the pinned ``base_url`` with a safe scheme.

    Args:
        base_url: The only origin requests may target.
        url: The exact request URL.

    Raises:
        TransportError: If the scheme is not http/https or the URL escapes
            the pinned base URL.
    """
    lowered = url.lower()
    if not (lowered.startswith("http://") or lowered.startswith("https://")):
        msg = f"Refusing non-HTTP(S) request URL: {url}"
        raise TransportError(msg)
    normalized_base = base_url.rstrip("/").lower()
    if not lowered.startswith(normalized_base + "/") and lowered != normalized_base:
        msg = f"Refusing request outside the configured endpoint: {url} (pinned to {base_url})"
        raise TransportError(msg)


class UrllibTransport:
    """Stdlib JSON/HTTP transport that pins every request to one base URL."""

    def __init__(self, base_url: str) -> None:
        """Pin this transport to a single endpoint origin.

        Args:
            base_url: Configured endpoint base, e.g. ``http://127.0.0.1:11434``.
        """
        self._base_url = base_url

    def post_json(
        self,
        url: str,
        payload: dict[str, Any],
        timeout_seconds: float,
    ) -> dict[str, Any]:
        """POST ``payload`` as JSON and decode the JSON response."""
        validate_pinned_url(self._base_url, url)
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        return self._execute(request, timeout_seconds)

    def get_json(self, url: str, timeout_seconds: float) -> dict[str, Any]:
        """GET ``url`` and decode the JSON response."""
        validate_pinned_url(self._base_url, url)
        return self._execute(urllib.request.Request(url), timeout_seconds)

    def _execute(self, request: urllib.request.Request, timeout_seconds: float) -> dict[str, Any]:
        """Perform the request and normalize failures into TransportError."""
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                body = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            msg = f"HTTP {exc.code} from {request.full_url}: {detail}"
            raise TransportError(msg) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            msg = f"Request to {request.full_url} failed: {exc}"
            raise TransportError(msg) from exc
        try:
            decoded: dict[str, Any] = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            msg = f"Endpoint {request.full_url} returned invalid JSON."
            raise TransportError(msg) from exc
        if not isinstance(decoded, dict):
            msg = f"Endpoint {request.full_url} returned unexpected JSON shape."
            raise TransportError(msg)
        return decoded
