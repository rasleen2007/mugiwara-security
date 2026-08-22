"""Remediation and code patch models for Mugiwara Security."""

from pydantic import BaseModel, Field


class Remediation(BaseModel):
    """Represents a proposed code fix and remediation plan for a verified finding."""

    explanation: str = Field(
        min_length=1,
        description="Technical explanation of how this fix resolves the vulnerability.",
    )
    target_file: str = Field(
        min_length=1,
        description="Path to the file to be patched.",
    )
    unified_diff: str = Field(
        min_length=1,
        description="Standard unified git diff patch resolving the issue.",
    )
    fixed_lines: tuple[int, int] | None = Field(
        default=None,
        description="Start and end line numbers affected by the patch (1-indexed).",
    )
    is_verified_fixed: bool = Field(
        default=False,
        description="Whether the patch was re-tested in the sandbox against the PoC and verified.",
    )
    references: list[str] = Field(
        default_factory=list,
        description="Relevant advisory, CWE, OWASP, or documentation references.",
    )
