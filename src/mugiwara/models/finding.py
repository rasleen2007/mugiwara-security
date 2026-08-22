"""Finding and vulnerability data models for Mugiwara Security."""

from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from mugiwara.models.evidence import Evidence
from mugiwara.models.remediation import Remediation


class FindingStatus(str, Enum):
    """Lifecycle status of a security finding."""

    SUSPECTED = "SUSPECTED"
    VERIFIED = "VERIFIED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    FIXED = "FIXED"


class Severity(str, Enum):
    """Standard vulnerability severity ratings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnerabilityCategory(str, Enum):
    """Common vulnerability categories and weakness types."""

    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    CROSS_SITE_SCRIPTING = "cross_site_scripting"
    SERVER_SIDE_REQUEST_FORGERY = "ssrf"
    PATH_TRAVERSAL = "path_traversal"
    INSECURE_DIRECT_OBJECT_REFERENCE = "idor"
    BROKEN_AUTHENTICATION = "broken_authentication"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    HARDCODED_SECRET = "hardcoded_secret"
    REMOTE_CODE_EXECUTION = "remote_code_execution"
    CROSS_SITE_REQUEST_FORGERY = "csrf"
    OTHER = "other"


class SourceLocation(BaseModel):
    """Represents a specific code location within a source file."""

    file_path: str = Field(
        min_length=1,
        description="Relative or absolute path to the target source file.",
    )
    start_line: int = Field(
        ge=1,
        description="Starting line number of the vulnerable code section (1-indexed).",
    )
    end_line: int | None = Field(
        default=None,
        ge=1,
        description="Ending line number of the vulnerable code section (1-indexed).",
    )
    start_column: int | None = Field(
        default=None,
        ge=1,
        description="Starting column character index (1-indexed).",
    )
    end_column: int | None = Field(
        default=None,
        ge=1,
        description="Ending column character index (1-indexed).",
    )
    snippet: str | None = Field(
        default=None,
        description="Code snippet surrounding the vulnerability location.",
    )


class Finding(BaseModel):
    """Represents a security vulnerability finding identified or verified by Mugiwara."""

    id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for the finding.",
    )
    title: str = Field(
        min_length=1,
        description="Concise summary title of the security vulnerability.",
    )
    description: str = Field(
        min_length=1,
        description="Detailed technical description of the vulnerability and its impact.",
    )
    category: VulnerabilityCategory = Field(
        description="Categorization of the vulnerability.",
    )
    severity: Severity = Field(
        description="Severity rating of the vulnerability.",
    )
    status: FindingStatus = Field(
        default=FindingStatus.SUSPECTED,
        description="Verification state of the finding.",
    )
    cwe_id: str | None = Field(
        default=None,
        description="Common Weakness Enumeration identifier (e.g., 'CWE-89').",
    )
    cvss_score: float | None = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="CVSS v3.1 base score (between 0.0 and 10.0).",
    )
    cvss_vector: str | None = Field(
        default=None,
        description="CVSS v3.1 vector string.",
    )
    location: SourceLocation | None = Field(
        default=None,
        description="Source code location where the vulnerability was identified.",
    )
    evidence: Evidence | None = Field(
        default=None,
        description="Reproducible verification proof, logs, or PoC traces.",
    )
    remediation: Remediation | None = Field(
        default=None,
        description="Proposed code patch and remediation guidance.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the finding was created (UTC).",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the finding was last updated (UTC).",
    )
