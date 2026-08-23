"""Agent-layer data transfer objects for reconnaissance, discovery, and verification.

These models are the strict schemas that LLM structured output must satisfy
and the internal carriers used between agents and the orchestrator.
"""

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

from mugiwara.models.finding import Severity, VulnerabilityCategory


class VerificationOutcome(str, Enum):
    """Deterministic result categories produced by PoC evaluation."""

    VERIFIED = "VERIFIED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    UNVERIFIED = "UNVERIFIED"
    SKIPPED = "SKIPPED"


class TechStackComponent(BaseModel):
    """A detected technology, framework, or library in the target codebase."""

    name: str = Field(min_length=1, description="Component name (e.g. 'FastAPI', 'PostgreSQL').")
    category: str = Field(
        min_length=1,
        description="Component category (e.g. 'language', 'framework', 'database', 'auth').",
    )
    confidence: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Detection confidence between 0.0 and 1.0.",
    )
    evidence_file: str | None = Field(
        default=None,
        description="Relative path of a collected file supporting this detection.",
    )


class Endpoint(BaseModel):
    """A discovered application endpoint from the attack surface map."""

    path: str = Field(min_length=1, description="Route path (e.g. '/api/users').")
    method: str | None = Field(default=None, description="HTTP method (e.g. 'GET', 'POST').")
    handler_hint: str | None = Field(
        default=None,
        description="Handler function or controller name if identifiable.",
    )
    auth_required: bool | None = Field(
        default=None,
        description="Whether the endpoint appears to require authentication.",
    )
    source_file: str | None = Field(
        default=None,
        description="Relative path of the collected file declaring this route.",
    )
    line_number: int | None = Field(
        default=None,
        ge=1,
        description="Line number of the route declaration (1-indexed).",
    )


class AttackSurfaceMap(BaseModel):
    """Structured map of detected technologies and exposed endpoints."""

    components: list[TechStackComponent] = Field(
        default_factory=list,
        description="Detected tech stack components.",
    )
    endpoints: list[Endpoint] = Field(
        default_factory=list,
        description="Discovered application endpoints.",
    )
    summary: str | None = Field(
        default=None,
        description="Short narrative describing the application architecture.",
    )


class SuspectedFinding(BaseModel):
    """A candidate vulnerability produced by semantic analysis.

    ``file_path`` must reference a file that was actually collected during the
    scan; findings referencing anything else are rejected by the confinement
    pass before they can become domain findings.
    """

    title: str = Field(min_length=1, description="Concise vulnerability title.")
    description: str = Field(min_length=1, description="Technical description and impact.")
    category: VulnerabilityCategory = Field(description="Vulnerability category enum value.")
    severity: Severity = Field(description="Severity enum value.")
    cwe_id: str | None = Field(default=None, description="CWE identifier (e.g. 'CWE-89').")
    file_path: str = Field(
        min_length=1,
        description="Relative path of the affected file within the scan target.",
    )
    start_line: int = Field(ge=1, description="Starting line number (1-indexed).")
    end_line: int | None = Field(default=None, ge=1, description="Ending line number (1-indexed).")
    rationale: str | None = Field(
        default=None,
        description="Reasoning explaining why this location is suspicious.",
    )


class SuspectedFindingsReport(BaseModel):
    """Container schema for the discovery agent's structured LLM response."""

    findings: list[SuspectedFinding] = Field(
        default_factory=list,
        description="Candidate vulnerabilities with locations inside the scanned target.",
    )


class VerificationPlan(BaseModel):
    """Structured LLM response describing one non-destructive PoC probe."""

    finding_ref: int = Field(
        ge=0,
        description="Index of the candidate finding this plan targets.",
    )
    poc_language: Literal["python3"] = Field(
        default="python3",
        description="Probe implementation language (only python3 is supported).",
    )
    poc_script: str = Field(
        min_length=1,
        description=(
            "Stdlib-only python3 probe that reads MUGIWARA_TARGET_URL and "
            "MUGIWARA_CANARY from os.environ and prints one final "
            "'MUGIWARA_VERDICT: {json}' line."
        ),
    )
    reproduction_steps: list[str] = Field(
        default_factory=list,
        description="Human-readable steps to reproduce the verification.",
    )
    expected_canary: str = Field(
        default="",
        description="Description of what observation counts as successful exploitation.",
    )
    max_readiness_wait_seconds: int = Field(
        default=5,
        ge=1,
        le=10,
        description="Seconds the probe is willing to wait for target readiness.",
    )


class RemediationPlan(BaseModel):
    """Structured LLM response proposing a full-file patch for one verified finding.

    The response must carry the complete new content of exactly one collected
    file; the remediation service computes the unified diff itself and re-runs
    the original PoC against the patched copy before any success is claimed.
    """

    finding_ref: int = Field(
        ge=0,
        description="Index of the verified finding this plan remediates.",
    )
    file_path: str = Field(
        min_length=1,
        description="Relative path of the single collected file to replace.",
    )
    patched_content: str = Field(
        min_length=1,
        description="Complete new file content replacing the target file.",
    )
    explanation: str = Field(
        min_length=1,
        description="Technical explanation of how the patch removes the vulnerability.",
    )


class HeuristicHit(BaseModel):
    """A deterministic regex-based dangerous-pattern match inside a collected file."""

    rule_id: str = Field(min_length=1, description="Identifier of the matching heuristic rule.")
    file_path: str = Field(min_length=1, description="Relative path within the scan target.")
    line_number: int = Field(ge=1, description="Line number of the match (1-indexed).")
    matched_line: str = Field(description="Trimmed content of the matching line.")
    category: VulnerabilityCategory = Field(description="Suggested vulnerability category.")
    severity: Severity = Field(description="Suggested severity rating.")
    cwe_id: str | None = Field(default=None, description="CWE identifier for the rule.")
    message: str = Field(description="Human-readable explanation of the matched pattern.")


class AgentDiagnostics(BaseModel):
    """Operational metrics and degradation flags accumulated during a scan session."""

    files_collected: int = Field(default=0, ge=0, description="Number of source files collected.")
    secret_markers_found: int = Field(
        default=0,
        ge=0,
        description="Number of secret-named files detected by name only (contents never read).",
    )
    llm_calls: int = Field(default=0, ge=0, description="Number of LLM calls attempted.")
    tokens_used: int = Field(
        default=0,
        ge=0,
        description="Total tokens recorded against the session budget.",
    )
    heuristic_hits: int = Field(default=0, ge=0, description="Number of heuristic matches found.")
    dropped_references: int = Field(
        default=0,
        ge=0,
        description=(
            "LLM references rejected because they pointed outside collected files "
            "or invalid line ranges."
        ),
    )
    degraded: bool = Field(
        default=False,
        description="Whether any phase fell back to reduced-capability operation.",
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Non-fatal error messages encountered per phase.",
    )
    verification_candidates: int = Field(
        default=0,
        ge=0,
        description="Number of suspected findings selected as verification candidates.",
    )
    verification_attempted: int = Field(
        default=0,
        ge=0,
        description="Number of PoC probes actually executed in the sandbox.",
    )
    verification_verified: int = Field(
        default=0,
        ge=0,
        description="Number of findings confirmed exploitable via PoC execution.",
    )
    verification_false_positives: int = Field(
        default=0,
        ge=0,
        description="Number of findings eliminated as false positives via clean probes.",
    )
    verification_unverified: int = Field(
        default=0,
        ge=0,
        description="Number of candidates whose probes were inconclusive or failed.",
    )
    sandbox_backend: str | None = Field(
        default=None,
        description="Sandbox backend used for dynamic verification, if any.",
    )
    staging_files: int = Field(
        default=0,
        ge=0,
        description="Number of files written into the disposable staging workspace.",
    )
