"""Unit tests for safe workspace source collection."""

from pathlib import Path
from typing import Any

import pytest

from mugiwara.agents.sources import (
    WorkspaceCollector,
    clamp_line_range,
    clamp_single_line,
    is_secret_named,
    is_within,
)
from mugiwara.core.config import AgentConfig
from mugiwara.core.exceptions import TargetPathError


def _config(**overrides: Any) -> AgentConfig:
    """Build an AgentConfig with optional field overrides."""
    values: dict[str, Any] = {"max_files": 50, "max_file_bytes": 65_536}
    values.update(overrides)
    return AgentConfig(**values)


def test_collects_allowed_files_sorted(tmp_path: Path) -> None:
    """Verify allowed extensions are collected in sorted relative-path order."""
    (tmp_path / "zeta.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "alpha.md").write_text("# doc\n", encoding="utf-8")
    sub = tmp_path / "pkg"
    sub.mkdir()
    (sub / "mod.py").write_text("y = 2\n", encoding="utf-8")

    result = WorkspaceCollector(_config()).collect(tmp_path)

    assert [item.relative_path for item in result.files] == [
        "alpha.md",
        "pkg/mod.py",
        "zeta.py",
    ]
    assert result.truncated_by_limit is False
    assert result.skipped_large_files == 0


def test_ignored_directories_are_skipped(tmp_path: Path) -> None:
    """Verify built-in ignore directories are pruned during traversal."""
    for ignored in (".git", "__pycache__", "node_modules", ".venv"):
        directory = tmp_path / ignored
        directory.mkdir()
        (directory / "leak.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "keep.py").write_text("y = 2\n", encoding="utf-8")

    result = WorkspaceCollector(_config()).collect(tmp_path)

    assert [item.relative_path for item in result.files] == ["keep.py"]


def test_user_ignore_patterns_applied(tmp_path: Path) -> None:
    """Verify configured glob patterns exclude matching paths."""
    (tmp_path / "app.py").write_text("a = 1\n", encoding="utf-8")
    (tmp_path / "app_generated.py").write_text("b = 2\n", encoding="utf-8")
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "lib.py").write_text("c = 3\n", encoding="utf-8")

    result = WorkspaceCollector(_config(ignore_patterns=["*_generated.py", "vendor/*"])).collect(
        tmp_path
    )

    assert [item.relative_path for item in result.files] == ["app.py"]


def test_disallowed_extensions_skipped(tmp_path: Path) -> None:
    """Verify files with unlisted extensions are not collected."""
    (tmp_path / "model.bin").write_bytes(b"\x01\x02\x03")
    (tmp_path / "script.py").write_text("x = 1\n", encoding="utf-8")

    result = WorkspaceCollector(_config()).collect(tmp_path)

    assert [item.relative_path for item in result.files] == ["script.py"]


def test_oversized_file_skipped_and_counted(tmp_path: Path) -> None:
    """Verify files exceeding max_file_bytes are excluded and counted."""
    (tmp_path / "big.py").write_text("x = 1\n" * 10_000, encoding="utf-8")
    (tmp_path / "small.py").write_text("y = 2\n", encoding="utf-8")

    result = WorkspaceCollector(_config(max_file_bytes=1024)).collect(tmp_path)

    assert [item.relative_path for item in result.files] == ["small.py"]
    assert result.skipped_large_files == 1


def test_binary_files_skipped(tmp_path: Path) -> None:
    """Verify NUL-byte content marks a file as binary and excludes it."""
    (tmp_path / "blob.py").write_bytes(b"x = 1\x00\x02")
    (tmp_path / "text.py").write_text("ok = True\n", encoding="utf-8")

    result = WorkspaceCollector(_config()).collect(tmp_path)

    assert [item.relative_path for item in result.files] == ["text.py"]


def test_secret_named_files_reported_but_never_collected(tmp_path: Path) -> None:
    """Verify credential-named files appear only as name markers."""
    (tmp_path / ".env").write_text("TOP_SECRET=1\n", encoding="utf-8")
    (tmp_path / "server.key").write_text("PRIVATE KEY DATA\n", encoding="utf-8")
    (tmp_path / "id_rsa").write_text("PRIVATE KEY\n", encoding="utf-8")
    (tmp_path / "main.py").write_text("z = 3\n", encoding="utf-8")

    result = WorkspaceCollector(_config()).collect(tmp_path)

    assert result.secret_markers == [".env", "id_rsa", "server.key"]
    assert [item.relative_path for item in result.files] == ["main.py"]
    assert all(".env" not in item.content for item in result.files)


def test_max_files_limit_truncates(tmp_path: Path) -> None:
    """Verify collection stops at the file cap and flags truncation."""
    for index in range(4):
        (tmp_path / f"f{index}.py").write_text(f"v{index} = {index}\n", encoding="utf-8")

    result = WorkspaceCollector(_config(max_files=2)).collect(tmp_path)

    assert len(result.files) == 2
    assert result.truncated_by_limit is True


def test_line_counts_match_content(tmp_path: Path) -> None:
    """Verify line counts reflect the collected content."""
    (tmp_path / "lines.py").write_text("one\ntwo\nthree\n", encoding="utf-8")

    result = WorkspaceCollector(_config()).collect(tmp_path)

    assert result.files[0].line_count == 3


def test_missing_target_raises(tmp_path: Path) -> None:
    """Verify nonexistent targets fail typed."""
    with pytest.raises(TargetPathError, match="does not exist"):
        WorkspaceCollector(_config()).collect(tmp_path / "missing")


def test_file_target_raises(tmp_path: Path) -> None:
    """Verify non-directory targets fail typed."""
    target_file = tmp_path / "not_a_dir.py"
    target_file.write_text("x = 1\n", encoding="utf-8")

    with pytest.raises(TargetPathError, match="must be a directory"):
        WorkspaceCollector(_config()).collect(target_file)


def test_is_within_rejects_outside_paths(tmp_path: Path) -> None:
    """Verify the containment guard accepts inside and rejects outside paths."""
    inside = tmp_path / "inside.txt"
    outside = tmp_path.parent / "outside.txt"

    assert is_within(tmp_path.resolve(), inside.resolve()) is True
    assert is_within(tmp_path.resolve(), tmp_path.resolve()) is True
    assert is_within(tmp_path.resolve(), outside.resolve()) is False


@pytest.mark.parametrize(
    ("start_line", "end_line", "line_count", "expected"),
    [
        (1, None, 10, 1),
        (10, None, 10, 10),
        (11, None, 10, None),
        (0, None, 10, None),
        (5, None, 0, None),
    ],
)
def test_clamp_line_range_cases(
    start_line: int,
    end_line: int | None,
    line_count: int,
    expected: int | None,
) -> None:
    """Verify line-range validation boundaries."""
    assert clamp_line_range(start_line, end_line, line_count) == expected


@pytest.mark.parametrize(
    ("line_number", "line_count", "expected"),
    [
        (None, 10, None),
        (5, 10, 5),
        (11, 10, None),
        (0, 10, None),
    ],
)
def test_clamp_single_line_cases(
    line_number: int | None,
    line_count: int,
    expected: int | None,
) -> None:
    """Verify single-line clamping behavior."""
    assert clamp_single_line(line_number, line_count) == expected


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (".env", True),
        (".env.local", True),
        ("server.pem", True),
        ("private.key", True),
        ("id_rsa", True),
        ("credentials.json", True),
        ("secrets.yaml", True),
        ("app.py", False),
        ("environment.txt", False),
        ("keyboard.py", False),
    ],
)
def test_is_secret_named(name: str, expected: bool) -> None:
    """Verify secret-name detection patterns."""
    assert is_secret_named(name) is expected
