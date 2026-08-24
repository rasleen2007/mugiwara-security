"""Supabase JWT verification with a cached, refreshing JWKS source.

Trust chain: the API accepts only RS256 access tokens whose signature
verifies against the Supabase Auth JWKS endpoint, and whose ``exp``, ``iss``
and ``aud`` claims are valid. The authenticated user is derived exclusively
from the verified ``sub`` claim; no client payload can influence identity or
ownership decisions.
"""

import threading
import time
import uuid as _uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx
import jwt

_RS256 = "RS256"
_RequiredClaims = ["exp", "iss", "aud", "sub"]


@dataclass(frozen=True)
class CurrentUser:
    """Identity extracted from a verified access token.

    Attributes:
        user_id: Canonical UUID string of the verified ``sub`` claim. This is
            the ONLY value the rest of the API may use as an owner id.
        email: Token email claim when present (informational).
        role: Supabase role claim when present (informational).
    """

    user_id: str
    email: str | None = None
    role: str | None = None


class AuthError(Exception):
    """Base class for authentication failures surfaced to clients."""

    status_code = 401

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class TokenExpiredError(AuthError):
    pass


class TokenInvalidError(AuthError):
    pass


class JwksUnavailableError(AuthError):
    status_code = 503


JwksFetcher = Callable[[str], Mapping[str, Any]]
Clock = Callable[[], float]


def _default_fetch(jwks_url: str) -> Mapping[str, Any]:
    response = httpx.get(jwks_url, timeout=10.0, headers={"Accept": "application/json"})
    response.raise_for_status()
    payload: Any = response.json()
    if not isinstance(payload, dict) or not isinstance(payload.get("keys"), list):
        msg = "JWKS document malformed"
        raise ValueError(msg)
    return payload


class JwksCache:
    """Thread-safe JWKS cache with TTL expiry and refresh-on-unknown-kid.

    Behavior:
    - Keys are cached per ``kid`` and considered fresh for ``ttl_seconds``.
    - A signature referencing an unknown kid triggers at most one forced
      refresh (rate limited by ``min_refresh_seconds`` when a cache exists),
      so key rotations converge without letting garbage kids hammer Supabase.
    - Fetch failures never clear an existing usable cache; they surface as
      :class:`JwksUnavailableError` only when no usable key can be produced.
    """

    def __init__(
        self,
        jwks_url: str,
        *,
        ttl_seconds: int = 600,
        min_refresh_seconds: int = 5,
        fetch: JwksFetcher | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._url = jwks_url
        self._ttl = ttl_seconds
        self._min_refresh = min_refresh_seconds
        self._fetch: JwksFetcher = fetch or _default_fetch
        self._clock: Clock = clock or time.time
        self._lock = threading.Lock()
        self._keys: dict[str, Any] = {}
        self._fetched_at: float | None = None

    def get_key(self, kid: str) -> tuple[Any, bool]:
        """Return ``(verification_key, was_refreshed_now)`` for ``kid``."""
        with self._lock:
            now = self._clock()
            cached_age = None if self._fetched_at is None else now - self._fetched_at
            if kid in self._keys and cached_age is not None and cached_age <= self._ttl:
                return self._keys[kid], False
            must_refresh = (
                not self._keys
                or cached_age is None
                or cached_age > self._ttl
                or cached_age >= self._min_refresh
            )
            if must_refresh:
                try:
                    keys = self._fetch_and_index()
                    self._keys = keys
                    self._fetched_at = now
                except AuthError:
                    if kid in self._keys:
                        return self._keys[kid], False
                    raise
                if kid in keys:
                    return keys[kid], True
            if kid in self._keys:
                return self._keys[kid], False
            raise TokenInvalidError("token references unknown signing key")

    def _fetch_and_index(self) -> dict[str, Any]:
        try:
            document = self._fetch(self._url)
        except AuthError:
            raise
        except Exception as exc:
            raise JwksUnavailableError("signing keys temporarily unavailable") from exc
        keys: dict[str, Any] = {}
        for entry in document.get("keys", []):
            if not isinstance(entry, dict) or "kid" not in entry:
                continue
            try:
                keys[str(entry["kid"])] = jwt.PyJWK.from_dict(dict(entry)).key
            except jwt.PyJWTError as exc:
                raise JwksUnavailableError("signing keys unusable") from exc
        if not keys:
            raise JwksUnavailableError("signing keys empty")
        return keys


class SupabaseTokenVerifier:
    """Verify Supabase access tokens and resolve the authenticated user."""

    def __init__(
        self,
        cache: JwksCache,
        *,
        issuer: str,
        audience: str = "authenticated",
        leeway_seconds: int = 30,
    ) -> None:
        self._cache = cache
        self._issuer = issuer.rstrip("/")
        self._audience = audience
        self._leeway = leeway_seconds

    def verify(self, token: str) -> CurrentUser:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise TokenInvalidError("malformed token") from exc
        alg = header.get("alg")
        if alg != _RS256:
            raise TokenInvalidError("unsupported signing algorithm")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise TokenInvalidError("missing key id")
        key, _refreshed = self._cache.get_key(kid)
        try:
            payload = jwt.decode(
                token,
                key=key,
                algorithms=[_RS256],
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options={"require": _RequiredClaims},
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenExpiredError("token expired") from exc
        except jwt.InvalidIssuerError as exc:
            raise TokenInvalidError("untrusted issuer") from exc
        except jwt.InvalidAudienceError as exc:
            raise TokenInvalidError("unexpected audience") from exc
        except jwt.PyJWTError as exc:
            raise TokenInvalidError("invalid token") from exc
        return _user_from_payload(payload)


def _user_from_payload(payload: Mapping[str, Any]) -> CurrentUser:
    sub = payload.get("sub")
    if not isinstance(sub, str):
        raise TokenInvalidError("subject missing")
    try:
        user_id = str(_uuid.UUID(sub))
    except (ValueError, AttributeError, TypeError) as exc:
        raise TokenInvalidError("subject is not a uuid") from exc
    email = payload.get("email")
    role = payload.get("role")
    return CurrentUser(
        user_id=user_id,
        email=email if isinstance(email, str) else None,
        role=role if isinstance(role, str) else None,
    )
