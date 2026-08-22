"""Disposable staging workspace assembled from pre-collected sources.

Dynamic verification must never run against (or mutate) the original scan
target. The orchestrator instead materializes exactly the files
:class:`~mugiwara.agents.sources.WorkspaceCollector` gathered into a temp
directory and mounts that directory into the sandbox. Secret-named files are
absent by construction because the collector never read them.
"""

import re
import shutil
import tempfile
from pathlib import Path, PurePosixPath
from types import TracebackType

from mugiwara.agents.poc_safety import HARMLESS_MARKER_TEXT
from mugiwara.agents.sources import CollectedSources

STAGING_MARKER_DIR = ".mugiwara"
STAGING_MARKER_FILE = "marker.txt"

_UNSAFE_SEGMENT = re.compile(r"^(?:\.\.?|)$")


class StagingWorkspace:
    """Temp-directory copy of collected sources, safe to mount read-write."""

    def __init__(self, sources: CollectedSources) -> None:
        """Store the sources to stage; nothing is written until __enter__."""
        self._sources = sources
        self._root: Path | None = None

    @property
    def root(self) -> Path:
        """Return the staging root path (valid only inside the context)."""
        if self._root is None:
            msg = "StagingWorkspace is not active; use it as a context manager."
            raise RuntimeError(msg)
        return self._root

    def _safe_target(self, relative_path: str) -> Path:
        """Resolve a collected relative path under the staging root."""
        parts = PurePosixPath(relative_path).parts
        if any(_UNSAFE_SEGMENT.match(part) for part in parts):
            msg = f"Refusing to stage unsafe relative path '{relative_path}'."
            raise ValueError(msg)
        target = (self.root / Path(*parts)).resolve()
        root_resolved = self.root.resolve()
        if not target.is_relative_to(root_resolved):
            msg = f"Staged path '{target}' escapes staging root '{root_resolved}'."
            raise ValueError(msg)
        return target

    def write_probe(self, name: str, content: str) -> Path:
        """Write a probe script into the staging marker directory."""
        probe_dir = self.root / STAGING_MARKER_DIR
        probe_dir.mkdir(exist_ok=True)
        safe_name = PurePosixPath(name).name
        probe_path = probe_dir / safe_name
        probe_path.write_text(content, encoding="utf-8")
        return probe_path

    def __enter__(self) -> "StagingWorkspace":
        """Materialize the staging tree and seed the harmless marker file."""
        self._root = Path(tempfile.mkdtemp(prefix="mugiwara-stage-"))
        for source in self._sources.files:
            target = self._safe_target(source.relative_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source.content, encoding="utf-8")
        marker_dir = self.root / STAGING_MARKER_DIR
        marker_dir.mkdir(exist_ok=True)
        (marker_dir / STAGING_MARKER_FILE).write_text(HARMLESS_MARKER_TEXT, encoding="utf-8")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Remove the staging tree on every exit path, tolerating absence."""
        if self._root is not None:
            shutil.rmtree(self._root, ignore_errors=True)
            self._root = None

    def file_count(self) -> int:
        """Return the number of staged source files (marker excluded)."""
        return len(self._sources.files)
