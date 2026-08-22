"""Unit tests for the disposable staging workspace."""

from pathlib import Path

import pytest

from mugiwara.agents.poc_safety import HARMLESS_MARKER_TEXT
from mugiwara.agents.sources import CollectedSources, SourceFile
from mugiwara.agents.staging import (
    STAGING_MARKER_DIR,
    STAGING_MARKER_FILE,
    StagingWorkspace,
)


def _source(relative_path: str, content: str) -> SourceFile:
    """Build a collected source file record."""
    return SourceFile(
        relative_path=relative_path,
        absolute_path=Path("/target") / relative_path,
        size_bytes=len(content.encode("utf-8")),
        line_count=len(content.splitlines()),
        content=content,
    )


def _sources(*files: SourceFile) -> CollectedSources:
    """Build a CollectedSources carrier from files (no secret markers)."""
    return CollectedSources(files=list(files), secret_markers=[])


def test_staging_materializes_exact_copy_of_collected_sources(tmp_path: Path) -> None:
    """Verify every collected file is written byte-for-byte under staging root."""
    sources = _sources(
        _source("app.py", "print('hello')\n"),
        _source("config/settings.yaml", "debug: true\n"),
        _source("routes.py", "GET /users\n"),
    )

    with StagingWorkspace(sources) as staging:
        assert (staging.root / "app.py").read_text(encoding="utf-8") == "print('hello')\n"
        assert (staging.root / "config" / "settings.yaml").read_text(
            encoding="utf-8"
        ) == "debug: true\n"
        assert (staging.root / "routes.py").exists()
        marker = staging.root / STAGING_MARKER_DIR / STAGING_MARKER_FILE
        assert marker.read_text(encoding="utf-8") == HARMLESS_MARKER_TEXT
        assert staging.file_count() == 3
        assert staging.root.exists()


def test_staging_cleanup_runs_on_success_and_exception(tmp_path: Path) -> None:
    """Verify the temp tree is always removed, even when the body raises."""
    sources = _sources(_source("app.py", "x = 1\n"))
    roots: list[Path] = []

    with StagingWorkspace(sources) as staging:
        roots.append(staging.root)

    with pytest.raises(RuntimeError, match="boom"), StagingWorkspace(sources) as staging:
        roots.append(staging.root)
        msg = "boom"
        raise RuntimeError(msg)

    for root in roots:
        assert not root.exists()


def test_staging_root_raises_when_inactive(tmp_path: Path) -> None:
    """Verify root access outside the context manager fails closed."""
    workspace = StagingWorkspace(_sources())

    with pytest.raises(RuntimeError, match="context manager"):
        _ = workspace.root


def test_staging_rejects_unsafe_relative_paths() -> None:
    """Verify traversal segments in collected paths are refused."""
    malicious = _sources(_source("../escape.py", "x = 1\n"))
    workspace = StagingWorkspace(malicious)

    with pytest.raises(ValueError, match="unsafe relative path"):
        workspace.__enter__()


def test_staging_write_probe_places_script_in_marker_dir(tmp_path: Path) -> None:
    """Verify probes land inside .mugiwara and names cannot traverse."""
    sources = _sources(_source("app.py", "x = 1\n"))

    with StagingWorkspace(sources) as staging:
        probe = staging.write_probe("poc_0.py", "print(1)\n")
        sneaky = staging.write_probe("../../evil.py", "print(2)\n")

        assert probe.parent.name == STAGING_MARKER_DIR
        assert probe.read_text(encoding="utf-8") == "print(1)\n"
        assert sneaky.parent == probe.parent
        assert sneaky.name == "evil.py"
