"""Safe target-source collection for agent analysis.

The collector is the single component allowed to read scan-target files.
It enforces every filesystem safety boundary: extension allowlisting,
directory ignore rules, secret-name exclusion (contents never read),
per-file size caps, file-count caps, binary rejection, and symlink-escape
refusal. LLM output never triggers additional filesystem reads; agents work
exclusively against what this collector gathered beforehand.
"""

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from mugiwara.core.config import AgentConfig
from mugiwara.core.exceptions import TargetPathError

DEFAULT_IGNORED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "dist",
        "build",
        ".eggs",
        ".idea",
        ".vscode",
        ".mugiwara",
    }
)

ALLOWED_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".rb",
        ".go",
        ".java",
        ".php",
        ".cs",
        ".rs",
        ".kt",
        ".swift",
        ".c",
        ".h",
        ".cpp",
        ".hpp",
        ".yml",
        ".yaml",
        ".json",
        ".toml",
        ".xml",
        ".md",
        ".txt",
        ".sql",
        ".sh",
        ".bash",
    }
)

SECRET_NAME_PATTERNS: tuple[str, ...] = (
    ".env*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "id_rsa*",
    "id_ecdsa*",
    "id_ed25519*",
    "*credential*",
    "*password*",
    "*secret*",
)

_BINARY_SNIFF_BYTES = 8_192


def is_secret_named(file_name: str) -> bool:
    """Return whether a file name looks like a credential store.

    Secret-named files are reported by name only; their contents are never
    loaded into memory or embedded in prompts.

    Args:
        file_name: Basename of the candidate file.

    Returns:
        True when the name matches a known credential pattern.
    """
    lowered = file_name.lower()
    return any(fnmatch.fnmatch(lowered, pattern) for pattern in SECRET_NAME_PATTERNS)


def is_within(root: Path, candidate: Path) -> bool:
    """Return whether ``candidate`` resolves inside ``root``.

    Both arguments must already be resolved paths. This is the symlink-escape
    guard applied to every collected file.

    Args:
        root: Resolved root directory.
        candidate: Resolved candidate file path.

    Returns:
        True when ``candidate`` is located under ``root``.
    """
    return candidate == root or candidate.is_relative_to(root)


@dataclass(frozen=True)
class SourceFile:
    """A collected target file with its decoded content preloaded."""

    relative_path: str
    absolute_path: Path
    size_bytes: int
    line_count: int
    content: str


@dataclass(frozen=True)
class CollectedSources:
    """Immutable snapshot of everything an agent session may reference."""

    files: list[SourceFile] = field(default_factory=list)
    secret_markers: list[str] = field(default_factory=list)
    skipped_large_files: int = 0
    truncated_by_limit: bool = False


def clamp_line_range(start_line: int, end_line: int | None, line_count: int) -> int | None:
    """Validate and clamp a reported line range against a real file length.

    Args:
        start_line: Reported starting line (1-indexed).
        end_line: Optional reported ending line.
        line_count: Actual number of lines in the referenced file.

    Returns:
        The validated (and clamped) starting line, or ``None`` when the
        reference points past the end of the file and is therefore invalid.
    """
    if start_line < 1 or start_line > line_count:
        return None
    return start_line


def clamp_single_line(line_number: int | None, line_count: int) -> int | None:
    """Clamp a single reported line number against a real file length.

    Args:
        line_number: Reported line number (may be None).
        line_count: Actual number of lines in the referenced file.

    Returns:
        The clamped line number, or None when absent or out of range.
    """
    if line_number is None or line_number < 1 or line_number > line_count:
        return None
    return line_number


class WorkspaceCollector:
    """Collects size-capped, ignore-aware, escape-checked source files."""

    def __init__(self, config: AgentConfig) -> None:
        """Store the collection limits to enforce.

        Args:
            config: Agent configuration providing caps and extra ignores.
        """
        self._config = config

    def collect(self, target: Path) -> CollectedSources:
        """Walk the target directory and gather analyzable sources.

        Args:
            target: Root directory of the authorized scan target.

        Returns:
            A CollectedSources snapshot with deterministic ordering.

        Raises:
            TargetPathError: If the target does not exist or is not a directory.
        """
        if not target.exists():
            msg = f"Scan target does not exist: {target}"
            raise TargetPathError(msg)
        if not target.is_dir():
            msg = f"Scan target must be a directory, got: {target}"
            raise TargetPathError(msg)

        root = target.resolve()
        files: list[SourceFile] = []
        secret_markers: list[str] = []
        skipped_large = 0
        truncated = False

        for current_dir, dir_names, file_names in os.walk(root):
            current_path = Path(current_dir)
            dir_names[:] = [
                name
                for name in sorted(dir_names)
                if name not in DEFAULT_IGNORED_DIRS
                and not self._is_user_ignored(
                    (current_path / name).relative_to(root).as_posix(), name
                )
            ]
            for name in sorted(file_names):
                if truncated:
                    break
                relative = (current_path / name).relative_to(root).as_posix()
                if self._is_user_ignored(relative, name):
                    continue
                if is_secret_named(name):
                    secret_markers.append(relative)
                    continue
                suffix = Path(name).suffix.lower()
                if suffix not in ALLOWED_EXTENSIONS:
                    continue
                absolute = current_path / name
                resolved = absolute.resolve()
                if not is_within(root, resolved):
                    continue
                size = resolved.stat().st_size
                if size > self._config.max_file_bytes:
                    skipped_large += 1
                    continue
                content_bytes = resolved.read_bytes()
                if b"\x00" in content_bytes[:_BINARY_SNIFF_BYTES]:
                    continue
                content = content_bytes.decode("utf-8", errors="replace")
                if len(files) >= self._config.max_files:
                    truncated = True
                    break
                files.append(
                    SourceFile(
                        relative_path=relative,
                        absolute_path=resolved,
                        size_bytes=size,
                        line_count=len(content.splitlines()),
                        content=content,
                    )
                )

            if truncated:
                break

        files.sort(key=lambda item: item.relative_path)
        secret_markers.sort()
        return CollectedSources(
            files=files,
            secret_markers=secret_markers,
            skipped_large_files=skipped_large,
            truncated_by_limit=truncated,
        )

    def _is_user_ignored(self, relative: str, name: str) -> bool:
        """Check user-configured ignore glob patterns.

        Args:
            relative: Posix-style path of the candidate relative to the root.
            name: Basename of the candidate.

        Returns:
            True when any configured pattern matches the basename, the full
            relative path, or any path segment beneath the root.
        """
        if not self._config.ignore_patterns:
            return False
        segments = [name, relative, *PurePosixPath(relative).parts]
        return any(
            fnmatch.fnmatch(candidate, pattern)
            for pattern in self._config.ignore_patterns
            for candidate in segments
        )
