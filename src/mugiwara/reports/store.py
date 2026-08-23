"""Durable, atomic, append-only storage for completed scan reports.

Reports live as one self-contained JSON document each under a caller-chosen
root (default ``.mugiwara/reports``). Every document carries the stable
envelope identifier ``mugiwara.scan-report`` so consumers can reject foreign
files cleanly, and wraps the existing
:class:`~mugiwara.models.report.ScanReport` unchanged - findings are never
re-modeled here.

Safety properties:

- Writes are atomic: content is fully written and flushed to a temporary
  file in the same directory, then moved into place with :func:`os.replace`,
  so an interrupted save can never leave a partial canonical report.
- Saves never overwrite: if the generated file name already exists, a fresh
  numeric suffix is chosen instead.
- Loading is strictly contained: bare identifiers must match the store's own
  ID grammar, and explicit paths are only accepted when they resolve inside
  the store root. Traversal attempts fail closed.
- Nothing in a stored report is ever executed; loading is pure validation.
- Configuration snapshots deliberately exclude credentials (the settings
  model keeps API keys in ``SecretStr`` fields that are simply not copied).
"""

import json
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mugiwara.core.config import MugiwaraSettings
from mugiwara.core.exceptions import (
    ReportFormatError,
    ReportInvalidContentsError,
    ReportNotFoundError,
    ReportPathEscapeError,
    ReportStoreError,
    UnsupportedSchemaError,
)
from mugiwara.models.report import ScanReport

SCHEMA_NAME: Final = "mugiwara.scan-report"

SCHEMA_VERSION: Final = 1

_REPORT_ID_PATTERN: re.Pattern[str] = re.compile(r"^[0-9]{8}T[0-9]{6}-[0-9a-f]{10}$")

_SUFFIX_PATTERN: re.Pattern[str] = re.compile(r"^(?P<base>.*)-(?P<n>[0-9]+)$")


def generate_report_id(now: datetime | None = None) -> str:
    """Return a unique, filename-safe report identifier.

    Args:
        now: Optional timestamp used instead of the current UTC time.

    Returns:
        An identifier of the form ``YYYYMMDDTHHMMSS-hhhhhhhhhh`` where the
        suffix is ten hex characters drawn from ``uuid4``.
    """
    moment = now or datetime.now(timezone.utc)
    stamp = moment.strftime("%Y%m%dT%H%M%S")
    return f"{stamp}-{uuid.uuid4().hex[:10]}"


class TargetMetadata(BaseModel):
    """Facts about what was scanned, kept separate from the scan itself."""

    path: str = Field(description="Resolved target directory that was analyzed.")
    origin: str = Field(description="Human-readable intake origin (directory or archive).")
    files_collected: int = Field(default=0, ge=0, description="Files collected by intake.")
    secret_markers_found: int = Field(
        default=0,
        ge=0,
        description="Credential-named files reported by name only (contents never read).",
    )


class ScanConfigurationSnapshot(BaseModel):
    """The configuration facts needed to interpret a stored report later.

    Credentials are intentionally absent; only non-secret operational
    choices are recorded.
    """

    scan_profile: str = Field(description="Scan profile in effect.")
    llm_provider: str = Field(description="LLM provider backend used.")
    llm_model: str = Field(description="Model identifier used.")
    sandbox_mode: str = Field(description="Sandbox backend mode.")
    verification_enabled: bool = Field(description="Whether dynamic verification ran.")
    include_evidence: bool = Field(description="Whether evidence was embedded in findings.")


def snapshot_from_settings(settings: MugiwaraSettings) -> ScanConfigurationSnapshot:
    """Derive a configuration snapshot from active settings.

    Args:
        settings: The settings the scan ran with.

    Returns:
        A credential-free snapshot of the interpretation-relevant fields.
    """
    return ScanConfigurationSnapshot(
        scan_profile=settings.scan.profile.value,
        llm_provider=settings.llm.provider.value,
        llm_model=settings.llm.model,
        sandbox_mode=settings.sandbox.mode.value,
        verification_enabled=settings.verification.enabled,
        include_evidence=settings.output.include_evidence,
    )


def resolve_report_root(
    settings: MugiwaraSettings,
    target_path: str | Path | None = None,
) -> Path:
    """Resolve the directory that should hold persisted scan reports.

    Precedence:

    1. An explicitly configured ``settings.output.reports_dir`` always wins.
    2. Otherwise the scanned project root anchors the default location at
       ``<target>/.mugiwara/reports``.
    3. With neither a configuration nor a target, the current working
       directory is used as the anchor.

    Args:
        settings: Active application settings.
        target_path: Scanned project root, when known.

    Returns:
        The resolved report store directory (not created).
    """
    configured = settings.output.reports_dir
    if configured:
        return Path(configured).expanduser().resolve()
    base = Path(target_path).expanduser().resolve() if target_path else Path.cwd()
    return base / ".mugiwara" / "reports"


def _with_authoritative_summary(report: ScanReport) -> ScanReport:
    """Return a copy whose summary block is recomputed from its findings.

    Stored or in-memory summary counters are never trusted; the findings
    list is the single source of truth.

    Args:
        report: Report whose findings are authoritative.

    Returns:
        A deep copy with freshly calculated summary metrics.
    """
    fresh = report.model_copy(deep=True)
    fresh.calculate_summary()
    return fresh


class StoredScanReport(BaseModel):
    """The on-disk envelope wrapping one immutable scan result.

    Attributes:
        schema_name: Stable envelope identifier, always ``mugiwara.scan-report``.
        schema_version: Envelope layout version for forward-compatible reads.
        report_id: Unique store identifier; also the canonical file stem.
        created_at: When the report was persisted (UTC).
        target: Metadata about the analyzed project.
        configuration: Interpretation-relevant, credential-free config.
        scan: The full existing domain scan report (findings included).
    """

    model_config = ConfigDict(populate_by_name=True)

    schema_name: Literal["mugiwara.scan-report"] = Field(alias="schema")
    schema_version: int
    report_id: str
    created_at: datetime
    target: TargetMetadata
    configuration: ScanConfigurationSnapshot
    scan: ScanReport


class ReportSummary(BaseModel):
    """Lightweight listing entry returned by :meth:`ReportStore.list_reports`."""

    report_id: str
    created_at: datetime
    target_path: str
    total_findings: int
    verified_count: int
    suspected_count: int


class ReportStore:
    """Filesystem-backed store providing save/load/list/delete for reports."""

    def __init__(self, root: str | Path = ".mugiwara/reports") -> None:
        """Point the store at its directory, creating it if needed.

        Args:
            root: Directory that holds one JSON document per report.
        """
        self._root = Path(root).resolve()
        self._root.mkdir(parents=True, exist_ok=True)

    @property
    def root(self) -> Path:
        """Return the resolved store root directory."""
        return self._root

    def save(
        self,
        report: ScanReport,
        *,
        target: TargetMetadata,
        configuration: ScanConfigurationSnapshot,
        now: datetime | None = None,
    ) -> StoredScanReport:
        """Persist a scan report as a new, non-overwriting envelope document.

        Args:
            report: Completed domain scan report to wrap.
            target: Metadata about the scanned project.
            configuration: Credential-free snapshot of run configuration.
            now: Optional timestamp override for the creation time/ID.

        Returns:
            The validated envelope that was written, carrying its final ID.

        Raises:
            ReportStoreError: If serialization or the atomic move fails.
        """
        moment = now or datetime.now(timezone.utc)
        report_id = generate_report_id(moment)
        envelope = StoredScanReport(
            schema=SCHEMA_NAME,
            schema_version=SCHEMA_VERSION,
            report_id=report_id,
            created_at=moment,
            target=target,
            configuration=configuration,
            scan=_with_authoritative_summary(report),
        )
        destination = self._path_for_new(report_id)
        payload = envelope.model_dump_json(indent=2, by_alias=True)
        self._atomic_write(destination, payload)
        return envelope.model_copy(update={"report_id": destination.stem})

    def load(self, reference: str) -> StoredScanReport:
        """Load and validate one stored report by ID, file name, or path.

        Bare identifiers and ``<id>.json`` names resolve inside the store
        root. Explicit paths are accepted only when they resolve within the
        root; anything else is refused as an escape attempt.

        Args:
            reference: Report ID, ``<id>.json``, or a path under the root.

        Returns:
            The validated envelope.

        Raises:
            ReportNotFoundError: If no such file exists in the store.
            ReportPathEscapeError: If the reference escapes the store root.
            ReportFormatError: If the file is not valid JSON.
            UnsupportedSchemaError: If the schema name/version is unknown.
            ReportInvalidContentsError: If the envelope does not validate.
        """
        candidate = self._resolve_reference(reference)
        try:
            raw_text = candidate.read_text(encoding="utf-8")
        except OSError as exc:
            msg = f"Report not found in store: {reference}"
            raise ReportNotFoundError(msg) from exc
        return parse_stored_report(raw_text)

    def list_reports(self) -> list[ReportSummary]:
        """Summarize every stored report, newest first.

        Corrupt or foreign files in the directory are skipped rather than
        making the whole history unreadable.

        Returns:
            Summaries ordered by ``(created_at, report_id)``, descending.
        """
        summaries: list[ReportSummary] = []
        for path in sorted(self._root.glob("*.json")):
            try:
                envelope = parse_stored_report(path.read_text(encoding="utf-8"))
            except ReportStoreError:
                continue
            summaries.append(
                ReportSummary(
                    report_id=envelope.report_id,
                    created_at=envelope.created_at,
                    target_path=envelope.target.path,
                    total_findings=envelope.scan.summary.total_findings,
                    verified_count=envelope.scan.summary.verified_count,
                    suspected_count=envelope.scan.summary.suspected_count,
                )
            )
        summaries.sort(key=lambda item: (item.created_at, item.report_id), reverse=True)
        return summaries

    def delete(self, report_id: str) -> None:
        """Remove one stored report permanently.

        Args:
            report_id: Exact report ID (or ``<id>.json``) to remove.

        Raises:
            ReportNotFoundError: If the report does not exist.
            ReportPathEscapeError: If the reference escapes the store root.
        """
        candidate = self._resolve_reference(report_id)
        try:
            candidate.unlink()
        except OSError as exc:
            msg = f"Report not found in store: {report_id}"
            raise ReportNotFoundError(msg) from exc

    # -- internals ---------------------------------------------------------

    def _path_for_new(self, report_id: str) -> Path:
        """Pick a free destination file name, never overwriting.

        Args:
            report_id: Generated base identifier.

        Returns:
            A path inside the root whose stem encodes the final report ID.
        """
        candidate = self._root / f"{report_id}.json"
        counter = 2
        while candidate.exists():
            match = _SUFFIX_PATTERN.match(candidate.stem)
            base = match.group("base") if match else candidate.stem
            candidate = self._root / f"{base}-{counter}.json"
            counter += 1
        return candidate

    def _resolve_reference(self, reference: str) -> Path:
        """Resolve a user reference to a concrete file inside the root.

        Args:
            reference: ID, file name, or relative/absolute path.

        Returns:
            The contained file path.

        Raises:
            ReportNotFoundError: If the reference is empty.
            ReportPathEscapeError: If it would resolve outside the root.
        """
        cleaned = reference.strip()
        if not cleaned:
            msg = "Empty report reference."
            raise ReportNotFoundError(msg)

        if _REPORT_ID_PATTERN.match(cleaned):
            candidate = self._root / f"{cleaned}.json"
        elif cleaned.endswith(".json") and _REPORT_ID_PATTERN.match(cleaned[: -len(".json")]):
            candidate = self._root / cleaned
        elif "/" in cleaned or "\\" in cleaned:
            supplied = Path(cleaned)
            candidate = supplied if supplied.is_absolute() else self._root / supplied
        else:
            candidate = self._root / f"{cleaned}.json"

        resolved = candidate.resolve()
        if not resolved.is_relative_to(self._root):
            msg = f"Report reference escapes the report store: {reference}"
            raise ReportPathEscapeError(msg)
        return resolved

    def _atomic_write(self, destination: Path, payload: str) -> None:
        """Write payload to destination atomically.

        The content is fully written into a uniquely named temporary file in
        the same directory, flushed to disk, then moved onto the destination
        with :func:`os.replace` (atomic on POSIX and Windows). If anything
        fails before the move, the temporary file is removed and the
        destination is left untouched - a partial canonical report is never
        observable.

        Args:
            destination: Final path of the report document.
            payload: Complete serialized JSON content.

        Raises:
            ReportStoreError: If the write or the move fails.
        """
        tmp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self._root,
                prefix=f".{destination.stem}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                tmp_path = Path(handle.name)
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, destination)
        except OSError as exc:
            if tmp_path is not None:
                tmp_path.unlink(missing_ok=True)
            msg = f"Failed to persist report {destination.name}: {exc}"
            raise ReportStoreError(msg) from exc


def parse_stored_report(raw_text: str) -> StoredScanReport:
    """Parse and validate raw JSON text as a stored scan report.

    Args:
        raw_text: File contents expected to be an envelope document.

    Returns:
        The validated envelope.

    Raises:
        UnsupportedSchemaError: If the schema name/version is missing or
            not one this code understands.
        ReportFormatError: If the text is not valid JSON at all.
        ReportInvalidContentsError: If it is valid JSON but fails envelope
            or inner ``ScanReport`` validation.

    Notes:
        The returned envelope always carries a summary recomputed from the
        underlying findings; stale stored summary counters are discarded.
    """
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        msg = f"Stored report is not valid JSON: {exc}"
        raise ReportFormatError(msg) from exc

    if not isinstance(payload, dict):
        msg = "Stored report must be a JSON object."
        raise ReportInvalidContentsError(msg)

    schema = payload.get("schema")
    version = payload.get("schema_version")
    if schema != SCHEMA_NAME or version != SCHEMA_VERSION:
        msg = (
            "Unsupported report schema "
            f"(expected {SCHEMA_NAME!r} version {SCHEMA_VERSION}, "
            f"got {schema!r} version {version!r})."
        )
        raise UnsupportedSchemaError(msg)

    try:
        envelope = StoredScanReport.model_validate(payload)
    except ValidationError as exc:
        msg = f"Stored report contents failed validation: {exc.error_count()} error(s)."
        raise ReportInvalidContentsError(msg) from exc

    envelope.scan = _with_authoritative_summary(envelope.scan)
    return envelope


__all__ = [
    "SCHEMA_NAME",
    "SCHEMA_VERSION",
    "ReportFormatError",
    "ReportInvalidContentsError",
    "ReportNotFoundError",
    "ReportPathEscapeError",
    "ReportStore",
    "ReportStoreError",
    "ReportSummary",
    "ScanConfigurationSnapshot",
    "StoredScanReport",
    "TargetMetadata",
    "UnsupportedSchemaError",
    "generate_report_id",
    "parse_stored_report",
    "resolve_report_root",
    "snapshot_from_settings",
]
