"""Request/response models for the cloud API.

Every request model sets ``extra="forbid"`` so that client attempts to inject
authority fields (``owner_id``, ``user_id``, ``status`` overrides, ...) are
rejected outright with a validation error instead of being silently ignored.
Response models expose only fields the owner may see; storage keys and
internal bookkeeping are deliberately excluded.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class MeOut(BaseModel):
    user_id: str
    email: str | None
    role: str | None


class ProjectCreate(_StrictModel):
    name: str = Field(min_length=1, max_length=200)


class ProjectUpdate(_StrictModel):
    name: str = Field(min_length=1, max_length=200)


class ProjectOut(BaseModel):
    id: str
    name: str
    created_at: datetime


class ScanProfile(str, Enum):
    FAST = "fast"
    STANDARD = "standard"
    DEEP = "deep"


class ScanJobCreate(_StrictModel):
    upload_path: str = Field(min_length=1, max_length=200)
    project_id: str | None = None
    scan_profile: ScanProfile = ScanProfile.STANDARD
    source_bytes: int | None = Field(default=None, ge=0)
    source_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )


class JobOut(BaseModel):
    id: str
    project_id: str | None
    kind: str
    status: str
    target_kind: str
    scan_profile: str
    phases: list[str]
    error: str | None
    attempts: int
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None


class SignedUploadOut(BaseModel):
    path: str
    upload_url: str
    expires_in: int


class SignedDownloadOut(BaseModel):
    download_url: str
    expires_in: int


class ReportOut(BaseModel):
    report_id: str
    project_id: str | None
    origin: str
    target_label: str
    summary: dict[str, Any]
    created_at: datetime


class ExportFormat(str, Enum):
    MARKDOWN = "markdown"
    SARIF = "sarif"
    JSON = "json"


EXPORT_MEDIA_TYPES: dict[ExportFormat, str] = {
    ExportFormat.MARKDOWN: "text/markdown; charset=utf-8",
    ExportFormat.SARIF: "application/sarif+json; charset=utf-8",
    ExportFormat.JSON: "application/json; charset=utf-8",
}

EXPORT_EXTENSIONS: dict[ExportFormat, str] = {
    ExportFormat.MARKDOWN: "md",
    ExportFormat.SARIF: "sarif",
    ExportFormat.JSON: "json",
}
