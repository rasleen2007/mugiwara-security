"""Source-egress policy and secret screening for LLM providers.

Two responsibilities live here:

1. **Locality policy** - a request may only leave the local machine when the
   user explicitly set ``llm.allow_remote: true``. The factory consults
   :func:`ensure_provider_egress_allowed` before constructing any provider,
   so a misconfigured ``api_base`` pointing at a remote host fails closed.

2. **Secret screening** - prompts derived from scanned source code are run
   through :func:`redact_source_secrets` before being sent to any non-local
   endpoint. This extends the existing name-only secret-marker detection in
   the collector with content-level redaction applied at the egress
   boundary. Local (loopback) endpoints skip redaction entirely so local
   analysis keeps full fidelity.
"""

import re
from urllib.parse import urlsplit

from mugiwara.core.config import LLMConfig
from mugiwara.core.exceptions import RemoteProviderNotAuthorizedError

LOCAL_HOSTNAMES = frozenset({"127.0.0.1", "localhost", "::1"})

DEFAULT_OLLAMA_LOCAL_BASE = "http://127.0.0.1:11434"

# Content-level secret indicators redacted before remote egress.
SECRET_CONTENT_PATTERNS: tuple[re.Pattern[str], ...] = (
    # AWS access key ids and generic cloud key ids
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    # GitHub / GitLab personal access & OAuth tokens
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgldt-[A-Za-z0-9]{20,}\b"),
    # Slack tokens
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    # Private key blocks in full
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
    # Bearer / token authorization headers
    re.compile(r"(?i)\b(authorization\s*[:=]\s*bearer\s+)[^\s'\"]+"),
    # Common credential assignment shapes: api_key = "value", password: value
    re.compile(
        r"(?i)\b((?:api[_-]?key|secret|password|passwd|token|access[_-]?key)"
        r"[a-z0-9_-]*\s*[:=]\s*)([\"']?)[^\s'\"#\n]{6,}\2"
    ),
    # Generic high-entropy-looking hex secrets assigned to names (32+ hex)
    re.compile(r"(?i)\b([a-z0-9_-]*(?:secret|token|key)[a-z0-9_-]*\s*[:=]\s*)([0-9a-f]{32,})\b"),
)

_REDACTED = "[REDACTED]"


def is_local_http_url(url: str) -> bool:
    """Return True when the URL targets this machine over http(s)."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return False
    hostname = (parts.hostname or "").lower()
    return hostname in LOCAL_HOSTNAMES


def resolve_provider_base_url(
    config: LLMConfig, default_base: str = DEFAULT_OLLAMA_LOCAL_BASE
) -> str:
    """Resolve the effective endpoint base URL for a provider config."""
    return (config.api_base or default_base).rstrip("/")


def ensure_provider_egress_allowed(config: LLMConfig, base_url: str) -> str:
    """Enforce the source-egress consent policy for one endpoint.

    Args:
        config: LLM configuration carrying the ``allow_remote`` decision.
        base_url: Resolved endpoint base URL the provider will contact.

    Returns:
        The validated base URL.

    Raises:
        RemoteProviderNotAuthorizedError: If the endpoint is not local and
            the user has not explicitly authorized remote egress.
    """
    if is_local_http_url(base_url):
        return base_url
    if config.allow_remote:
        return base_url
    msg = (
        f"Endpoint '{base_url}' is not on the local machine. Mugiwara never "
        "sends your source code off this computer by default. To authorize "
        "remote egress explicitly, set 'llm.allow_remote: true' in your "
        "configuration."
    )
    raise RemoteProviderNotAuthorizedError(msg)


def redact_source_secrets(text: str) -> str:
    """Redact credential-shaped content from text bound for remote endpoints.

    Args:
        text: Prompt or payload fragment potentially containing source code.

    Returns:
        Text with every recognized secret replaced by ``[REDACTED]``.
    """
    redacted = text
    for pattern in SECRET_CONTENT_PATTERNS:
        redacted = pattern.sub(_replace_match, redacted)
    return redacted


def _replace_match(match: re.Match[str]) -> str:
    """Keep any prefix group (assignment/label) intact, redact the value."""
    groups = match.groups()
    if groups and groups[0]:
        return groups[0] + _REDACTED
    return _REDACTED
