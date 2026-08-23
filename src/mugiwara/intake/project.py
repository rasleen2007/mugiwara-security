"""Safe project intake: validated local directories and hardened ZIP extraction.

Intake is the only new filesystem surface in Phase 7 and it is deliberately
narrow: a directory input is resolved and verified to exist, and a ZIP input
is extracted into a disposable temporary directory that Mugiwara itself
created. Every archive member is screened before a single byte is written:
absolute paths, ``..`` traversal, drive letters, symlink/device members,
encrypted entries, and per-member/total/entry-count overruns are all rejected.

The extracted tree (or the user's original directory) is then handed to the
existing :class:`~mugiwara.agents.sources.WorkspaceCollector`, which remains
the sole component allowed to read target content. Intake never writes inside
the user's project; temporary extractions live under the platform temp
directory and are removed when the surrounding :class:`DisposableIntake`
context exits.
"""

import shutil
import stat
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

from mugiwara.core.exceptions import ArchiveRejectedError, TargetNotAvailableError

_COPY_CHUNK_BYTES: Final = 1024 * 1024

_DEFAULT_MAX_ENTRIES: Final = 5_000

_DEFAULT_MAX_TOTAL_BYTES: Final = 256 * 1024 * 1024

_DEFAULT_MAX_MEMBER_BYTES: Final = 64 * 1024 * 1024


@dataclass(frozen=True)
class IntakeLimits:
    """Safety caps enforced during archive extraction.

    Attributes:
        max_entries: Maximum number of members (files plus directories).
        max_total_bytes: Maximum combined uncompressed size of all members.
        max_member_bytes: Maximum uncompressed size of any single member.
    """

    max_entries: int = _DEFAULT_MAX_ENTRIES
    max_total_bytes: int = _DEFAULT_MAX_TOTAL_BYTES
    max_member_bytes: int = _DEFAULT_MAX_MEMBER_BYTES

    def __post_init__(self) -> None:
        """Reject non-positive limits so misconfiguration fails closed."""
        if self.max_entries < 1 or self.max_total_bytes < 1 or self.max_member_bytes < 1:
            msg = "IntakeLimits must be positive integers."
            raise ValueError(msg)


@dataclass(frozen=True)
class IntakeTarget:
    """A validated, ready-to-scan project root produced by intake.

    Attributes:
        target_path: Resolved existing directory containing the project.
        origin: Human-readable description of where the project came from.
        temporary: True when ``target_path`` is disposable and will be
            deleted by :class:`DisposableIntake`.
        cleanup_root: Directory to delete on teardown; defaults to
            ``target_path``. ZIP extraction sets this to the full
            disposable extraction tree so nested project roots never
            leave wrapper directories behind.
    """

    target_path: Path
    origin: str
    temporary: bool
    cleanup_root: Path | None = None


class DisposableIntake:
    """Context manager owning the lifetime of an intake target.

    Temporary extraction trees are removed on exit; real user directories
    are never touched. Cleanup failures are swallowed deliberately so an
    interrupted scan can never mask its real outcome with a deletion error.
    """

    def __init__(self, target: IntakeTarget) -> None:
        """Store the owned target.

        Args:
            target: An intake target returned by ``open_*_target``.
        """
        self._target = target
        self._entered = False

    @property
    def target(self) -> IntakeTarget:
        """Return the owned intake target."""
        return self._target

    def __enter__(self) -> IntakeTarget:
        """Mark the target as owned and return it.

        Returns:
            The intake target to scan.
        """
        self._entered = True
        return self._target

    def __exit__(self, *exc_info: object) -> None:
        """Remove the temporary tree if one exists; leave user dirs alone."""
        if self._entered and self._target.temporary:
            victim = self._target.cleanup_root or self._target.target_path
            shutil.rmtree(victim, ignore_errors=True)


def open_directory_target(raw_path: str | Path) -> IntakeTarget:
    """Validate an explicit local project directory for scanning.

    The path is expanded (``~``), resolved against the real filesystem, and
    must exist as a directory. Nothing is written and nothing is modified.

    Args:
        raw_path: User-supplied path to an authorized source-code project.

    Returns:
        An :class:`IntakeTarget` describing a non-temporary project root.

    Raises:
        TargetNotAvailableError: If the path does not exist or is not a
            directory.
    """
    candidate = Path(str(raw_path)).expanduser()
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        msg = f"Project directory could not be resolved: {raw_path} ({exc})"
        raise TargetNotAvailableError(msg) from exc
    if not resolved.is_dir():
        msg = f"Scan target must be an existing directory, got: {resolved}"
        raise TargetNotAvailableError(msg)
    return IntakeTarget(target_path=resolved, origin=str(resolved), temporary=False)


def open_zip_target(
    zip_path: str | Path,
    *,
    limits: IntakeLimits | None = None,
    work_root: Path | None = None,
) -> DisposableIntake:
    """Extract a local ZIP archive into a fresh disposable directory.

    The archive is opened and fully screened before extraction begins;
    every member is re-validated at write time so a crafted archive cannot
    escape the extraction root even via race-style tricks. The returned
    context manager deletes the entire extraction tree on exit.

    Args:
        zip_path: Path to the uploaded/local ZIP file.
        limits: Optional override of extraction safety caps.
        work_root: Optional parent directory for the temp extraction
            (defaults to the platform temp dir). Used by tests.

    Returns:
        A :class:`DisposableIntake`; enter it to obtain the target.

    Raises:
        TargetNotAvailableError: If the ZIP path does not exist or is not a
            file.
        ArchiveRejectedError: If the file is not a readable ZIP, contains
            unsafe members, or violates the configured limits.
    """
    effective_limits = limits or IntakeLimits()
    archive = Path(str(zip_path)).expanduser()
    if not archive.is_file():
        msg = f"ZIP archive not found: {archive}"
        raise TargetNotAvailableError(msg)

    try:
        with zipfile.ZipFile(archive) as zf:
            _screen_archive(zf, effective_limits)
    except zipfile.BadZipFile as exc:
        msg = f"File is not a readable ZIP archive: {archive} ({exc})"
        raise ArchiveRejectedError(msg) from exc

    parent = work_root if work_root is not None else Path(tempfile.gettempdir())
    parent.mkdir(parents=True, exist_ok=True)
    extraction_root = Path(tempfile.mkdtemp(prefix="mugiwara-intake-", dir=str(parent)))

    try:
        with zipfile.ZipFile(archive) as zf:
            project_root = _extract_members(zf, extraction_root, effective_limits)
    except BaseException:
        shutil.rmtree(extraction_root, ignore_errors=True)
        raise

    if project_root is None:
        shutil.rmtree(extraction_root, ignore_errors=True)
        msg = "ZIP archive contains no files."
        raise ArchiveRejectedError(msg)

    target = IntakeTarget(
        target_path=project_root,
        origin=f"{archive.name} (extracted)",
        temporary=True,
        cleanup_root=extraction_root,
    )
    return DisposableIntake(target)


def _screen_archive(zf: zipfile.ZipFile, limits: IntakeLimits) -> None:
    """Validate every archive member against safety rules and limits.

    Args:
        zf: Open archive.
        limits: Extraction caps to enforce.

    Raises:
        ArchiveRejectedError: On any unsafe member or limit violation.
    """
    infos = zf.infolist()
    if len(infos) > limits.max_entries:
        msg = (
            f"ZIP archive has {len(infos)} entries which exceeds the limit of {limits.max_entries}."
        )
        raise ArchiveRejectedError(msg)

    total_bytes = 0
    file_count = 0
    for info in infos:
        normalized = _safe_member_name(info.filename)
        if info.flag_bits & 0x1:
            msg = f"ZIP entry is encrypted: {info.filename}"
            raise ArchiveRejectedError(msg)
        mode = (info.external_attr >> 16) & 0xFFFF
        if stat.S_IFMT(mode) == stat.S_IFLNK:
            msg = f"ZIP entry is a symbolic link: {info.filename}"
            raise ArchiveRejectedError(msg)
        # Permission-only attrs (no file-type bits, e.g. from Python's
        # writestr) and explicit regular/directory types are allowed;
        # devices, FIFOs, and other special types are rejected.
        if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
            msg = f"ZIP entry is not a regular file or directory: {info.filename}"
            raise ArchiveRejectedError(msg)
        if info.is_dir():
            continue
        file_count += 1
        declared = info.file_size
        if declared > limits.max_member_bytes:
            msg = (
                f"ZIP entry '{normalized}' declares {declared} bytes which "
                f"exceeds the per-file limit of {limits.max_member_bytes}."
            )
            raise ArchiveRejectedError(msg)
        total_bytes += declared
        if total_bytes > limits.max_total_bytes:
            msg = (
                f"ZIP archive decompresses beyond the total size limit of "
                f"{limits.max_total_bytes} bytes."
            )
            raise ArchiveRejectedError(msg)

    if file_count == 0:
        msg = "ZIP archive contains no files."
        raise ArchiveRejectedError(msg)


def _safe_member_name(name: str) -> str:
    """Normalize and validate one archive member name.

    Backslashes are treated as separators (Windows-produced archives), then
    the resulting POSIX path must stay inside the extraction root: absolute
    paths, drive letters, UNC prefixes, empty segments from double slashes,
    and any ``..`` component are rejected outright.

    Args:
        name: Raw member name from the archive.

    Returns:
        The normalized POSIX-style relative name safe to join.

    Raises:
        ArchiveRejectedError: If the name attempts to escape the extraction
            root in any way.
    """
    if "\x00" in name:
        msg = "ZIP entry name contains a NUL byte."
        raise ArchiveRejectedError(msg)
    lowered = name.replace("\\", "/")
    pure = PurePosixPath(lowered)
    if pure.is_absolute():
        msg = f"ZIP entry uses an absolute path: {name}"
        raise ArchiveRejectedError(msg)
    parts = list(pure.parts)
    if not parts:
        msg = f"ZIP entry has an empty path: {name!r}"
        raise ArchiveRejectedError(msg)
    for part in parts:
        if part == "..":
            msg = f"ZIP entry escapes the extraction directory: {name}"
            raise ArchiveRejectedError(msg)
        if len(part) >= 2 and part[1] == ":" and part[0].isalpha():
            msg = f"ZIP entry uses a drive-letter path: {name}"
            raise ArchiveRejectedError(msg)
    joined = "/".join(parts)
    if lowered.startswith("//") or lowered.startswith("../"):
        msg = f"ZIP entry escapes the extraction directory: {name}"
        raise ArchiveRejectedError(msg)
    return joined


def _member_destination(root: Path, safe_name: str) -> Path:
    """Join a screened member name onto the extraction root defensively.

    Even after name screening the join is re-resolved and containment is
    re-checked, so no sequence of names can produce a destination outside
    ``root``.

    Args:
        root: The disposable extraction root.
        safe_name: Output of :func:`_safe_member_name`.

    Returns:
        Destination path guaranteed to reside under ``root``.

    Raises:
        ArchiveRejectedError: If containment fails (defensive backstop).
    """
    candidate = (root / safe_name).resolve()
    resolved_root = root.resolve()
    if candidate != resolved_root and not candidate.is_relative_to(resolved_root):
        msg = f"ZIP entry would extract outside the disposable directory: {safe_name}"
        raise ArchiveRejectedError(msg)
    return candidate


def _extract_members(
    zf: zipfile.ZipFile,
    extraction_root: Path,
    limits: IntakeLimits,
) -> Path | None:
    """Write every screened member into the disposable extraction tree.

    Directory entries are created as needed. File contents are streamed in
    chunks with a running byte counter so a lying header cannot overflow the
    disk budget. Returns the project root: the single top-level directory if
    all files share exactly one, otherwise the extraction root itself.

    Args:
        zf: Screened open archive.
        extraction_root: Fresh disposable directory to fill.
        limits: Extraction caps (re-enforced during streaming).

    Returns:
        The discovered project root, or ``None`` when no regular files
        were written.

    Raises:
        ArchiveRejectedError: On streaming overrun or unreadable member.
    """
    total_written = 0
    first_parts: set[tuple[str, ...]] = set()

    for info in zf.infolist():
        safe_name = _safe_member_name(info.filename)
        destination = _member_destination(extraction_root, safe_name)
        if info.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
            continue
        parts = tuple(PurePosixPath(safe_name).parts)
        if parts:
            first_parts.add(parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        written_for_member = 0
        try:
            with zf.open(info) as source, destination.open("wb") as sink:
                while True:
                    chunk = source.read(_COPY_CHUNK_BYTES)
                    if not chunk:
                        break
                    written_for_member += len(chunk)
                    total_written += len(chunk)
                    if written_for_member > limits.max_member_bytes:
                        msg = (
                            f"ZIP entry '{safe_name}' exceeds the per-file "
                            f"limit of {limits.max_member_bytes} bytes."
                        )
                        raise ArchiveRejectedError(msg)
                    if total_written > limits.max_total_bytes:
                        msg = (
                            f"ZIP archive exceeds the total size limit of "
                            f"{limits.max_total_bytes} bytes."
                        )
                        raise ArchiveRejectedError(msg)
                    sink.write(chunk)
        except ArchiveRejectedError:
            raise
        except (OSError, zipfile.BadZipFile, NotImplementedError, RuntimeError) as exc:
            msg = f"Failed to extract ZIP entry '{safe_name}': {exc}"
            raise ArchiveRejectedError(msg) from exc

    if not first_parts:
        return None

    shared_root = next(iter(first_parts))[0]
    if all(parts[0] == shared_root for parts in first_parts):
        single = _member_destination(extraction_root, shared_root)
        if single.is_dir():
            return single
    return extraction_root


__all__ = [
    "DisposableIntake",
    "IntakeLimits",
    "IntakeTarget",
    "open_directory_target",
    "open_zip_target",
]
