"""Remediation service: AI-proposed patches, isolated application, sea trials.

Phase 6 turns dynamically verified findings into *proven* fixes. For each
VERIFIED finding the service asks the LLM for a full-file patch, confines it
to collected sources, applies it to a disposable staging copy only, and then
re-executes the ORIGINAL PoC script with the ORIGINAL canary token against the
patched target inside the sandbox. The exploit must demonstrably stop
reproducing before a record may claim VERIFIED_FIXED; anything inconclusive
or operationally broken is honestly reported as FAILED or NOT_FIXED.
"""

from mugiwara.remediation.patches import (
    build_unified_diff,
    sha256_text,
    validate_python_source,
)
from mugiwara.remediation.service import (
    RemediationRunResult,
    RemediationService,
    build_remediation_bundle,
)

__all__ = [
    "RemediationRunResult",
    "RemediationService",
    "build_remediation_bundle",
    "build_unified_diff",
    "sha256_text",
    "validate_python_source",
]
