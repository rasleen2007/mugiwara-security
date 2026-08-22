"""Evidence and verification trace models for Mugiwara Security."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

# Common sensitive header names that should be redacted
SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "session",
        "token",
    }
)


def sanitize_headers(headers: dict[str, str], placeholder: str = "[REDACTED]") -> dict[str, str]:
    """Return a copy of headers with sensitive authorization and cookie values redacted."""
    sanitized: dict[str, str] = {}
    for key, value in headers.items():
        if key.strip().lower() in SENSITIVE_HEADERS:
            sanitized[key] = placeholder
        else:
            sanitized[key] = value
    return sanitized


class HTTPTrace(BaseModel):
    """Represents captured HTTP request and response trace used in vulnerability verification."""

    method: str = Field(
        description="HTTP request method (e.g. 'GET', 'POST').",
    )
    url: str = Field(
        description="Target request URL.",
    )
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="HTTP request headers (sensitive keys should be redacted).",
    )
    body: str | None = Field(
        default=None,
        description="HTTP request payload body.",
    )
    response_status_code: int | None = Field(
        default=None,
        ge=100,
        le=599,
        description="HTTP response status code.",
    )
    response_headers: dict[str, str] = Field(
        default_factory=dict,
        description="HTTP response headers.",
    )
    response_body_snippet: str | None = Field(
        default=None,
        description="Snippet or relevant excerpt of the HTTP response body.",
    )

    def model_post_init(self, __context: Any) -> None:
        """Sanitize sensitive headers upon initialization to prevent secret leakage."""
        if self.headers:
            self.headers = sanitize_headers(self.headers)
        if self.response_headers:
            self.response_headers = sanitize_headers(self.response_headers)


class Evidence(BaseModel):
    """Represents verifiable evidence and dynamic execution output supporting a finding."""

    poc_script: str | None = Field(
        default=None,
        description="Proof of Concept script, curl command, or payload string.",
    )
    reproduction_steps: list[str] = Field(
        default_factory=list,
        description="Sequential list of steps required to reproduce the vulnerability.",
    )
    http_trace: HTTPTrace | None = Field(
        default=None,
        description="Captured HTTP request/response exchange if applicable.",
    )
    stdout_log: str | None = Field(
        default=None,
        description="Standard output captured during PoC execution.",
    )
    stderr_log: str | None = Field(
        default=None,
        description="Standard error captured during PoC execution.",
    )
    canary_found: bool = Field(
        default=False,
        description="Whether a benign canary token was successfully triggered/observed.",
    )
    canary_token: str | None = Field(
        default=None,
        description="Benign canary token identifier used in verification.",
    )
    verified_at: datetime | None = Field(
        default=None,
        description="Timestamp when verification completed (UTC).",
    )
    sandbox_runtime_seconds: float | None = Field(
        default=None,
        ge=0.0,
        description="Total duration in seconds spent executing dynamic verification in sandbox.",
    )
