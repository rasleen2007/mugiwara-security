"""Static PoC safety screening and canary-token primitives.

Synthesized PoC scripts never run unreviewed: :func:`screen_poc` applies a
deterministic deny-rule set (destructive filesystem operations, destructive
SQL verbs including blanket ``UPDATE``/``DELETE`` denial, non-loopback
network egress, reverse shells, process-control and privilege operations)
plus a probe-code call denylist applied outside quoted strings, an import
allowlist, a size cap, and a target-URL contract check. Screening is
conservative by design; anything ambiguous is rejected.
"""

import re
from dataclasses import dataclass, field
from uuid import uuid4

CANARY_PREFIX = "MUGIWARA_CANARY_"

TARGET_URL_ENV_VAR = "MUGIWARA_TARGET_URL"
CANARY_ENV_VAR = "MUGIWARA_CANARY"

VERDICT_PREFIX = "MUGIWARA_VERDICT: "
HTTP_TRACE_PREFIX = "MUGIWARA_HTTP_TRACE: "
TARGET_LOG_MARKER = "===MUGIWARA_TARGET_LOG==="
POC_LOG_MARKER = "===MUGIWARA_POC_LOG==="

HARMLESS_MARKER_TEXT = "mugiwara-harmless-verification-marker"


def gen_canary_token() -> str:
    """Return a unique benign canary token for one verification attempt."""
    return f"{CANARY_PREFIX}{uuid4().hex[:12]}"


@dataclass(frozen=True)
class ScreeningResult:
    """Outcome of static PoC screening."""

    allowed: bool
    reasons: list[str] = field(default_factory=list)


_ALLOWED_IMPORT_ROOTS = frozenset(
    {"urllib", "http", "json", "re", "sys", "time", "base64", "uuid", "os"}
)

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})

# Deny rules evaluated against the raw script text.
_RAW_DENY_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "destructive SQL verb",
        re.compile(r"\b(DROP|DELETE|TRUNCATE|ALTER|UPDATE)\b", re.IGNORECASE),
    ),
    ("destructive file removal", re.compile(r"\brm\s+")),
    ("filesystem destruction tool", re.compile(r"\bmkfs\b|\bdd\s+if=")),
    (
        "raw device write",
        re.compile(r">\s*/dev/(sd|hd|nvme|vd)|of=/dev/(sd|hd|nvme|vd)"),
    ),
    ("world-writable root", re.compile(r"chmod\s+777\s+/(\s|$)")),
    ("reverse shell construct", re.compile(r"/dev/tcp/|bash\s+-i\b|nc\s+-e\b|socat\b")),
    (
        "process-control command",
        re.compile(r"\b(shutdown|reboot|halt|poweroff|killall)\b|kill\s+-9\s+1\b"),
    ),
    ("fork bomb", re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:")),
)

# Deny rules for probe code only (evaluated with quoted strings removed so
# payloads riding inside request bodies do not trigger false rejections).
_PROBE_CALL_DENY_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("probe process execution", re.compile(r"\bos\.system\s*\(|\bsubprocess\.|\bpopen\s*\(")),
    ("probe dynamic evaluation", re.compile(r"\beval\s*\(|\bexec\s*\(")),
    ("probe file access", re.compile(r"\bopen\s*\(")),
)

_URL_PATTERN = re.compile(r"""https?://([^/'"\s>]+)""", re.IGNORECASE)

_IMPORT_PATTERN = re.compile(r"""^\s*(?:import|from)\s+([A-Za-z_][\w.]*)""", re.MULTILINE)


def _strip_quoted(script: str) -> str:
    """Remove contents of single/double-quoted string literals."""
    return re.sub(r"'[^'\n]*'|\"[^\"\n]*\"", '""', script)


def _check_urls(script: str, reasons: list[str]) -> None:
    """Reject any URL whose host is not the in-container loopback."""
    for host in _URL_PATTERN.findall(script):
        hostname = host.strip().lower()
        if hostname not in _LOOPBACK_HOSTS and not hostname.startswith("127.0.0.1"):
            reasons.append(f"non-loopback URL literal '{host}'")


def screen_poc(script: str, *, max_bytes: int) -> ScreeningResult:
    """Statically screen a synthesized PoC before it may execute.

    Args:
        script: The candidate python3 probe source.
        max_bytes: Maximum permitted script size in bytes.

    Returns:
        A ScreeningResult whose ``allowed`` is True only when every rule passes.
    """
    reasons: list[str] = []

    if len(script.encode("utf-8")) > max_bytes:
        reasons.append(f"script exceeds {max_bytes} byte cap")

    if TARGET_URL_ENV_VAR not in script:
        reasons.append("script must reference the MUGIWARA_TARGET_URL environment variable")

    _check_urls(script, reasons)

    for label, pattern in _RAW_DENY_RULES:
        if pattern.search(script):
            reasons.append(f"forbidden construct detected: {label}")

    stripped = _strip_quoted(script)
    for label, pattern in _PROBE_CALL_DENY_RULES:
        if pattern.search(stripped):
            reasons.append(f"forbidden probe call: {label}")

    for import_line in _IMPORT_PATTERN.finditer(stripped):
        root = import_line.group(1).split(".", 1)[0]
        if root not in _ALLOWED_IMPORT_ROOTS:
            reasons.append(f"disallowed import '{root}'")

    return ScreeningResult(allowed=not reasons, reasons=reasons)
