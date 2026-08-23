"""Unit tests for safe source-project intake (directory + ZIP)."""

import hashlib
import io
import os
import stat
import zipfile
from pathlib import Path

import pytest

from mugiwara.agents.sources import WorkspaceCollector
from mugiwara.core.config import AgentConfig
from mugiwara.core.exceptions import (
    ArchiveRejectedError,
    IntakeError,
    MugiwaraError,
    TargetNotAvailableError,
)
from mugiwara.intake import (
    DisposableIntake,
    IntakeLimits,
    open_directory_target,
    open_zip_target,
)
from mugiwara.intake.project import _safe_member_name, _screen_archive


def _make_zip(path: Path, members: dict[str, bytes]) -> None:
    """Write a ZIP archive with plain deflate members."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, payload in members.items():
            zf.writestr(name, payload)


def _tree_signature(root: Path) -> dict[str, tuple[int, bytes]]:
    """Return a comparable signature of every file under root."""
    signature: dict[str, tuple[int, bytes]] = {}
    for current, _dirs, names in os.walk(root):
        for name in sorted(names):
            file_path = Path(current) / name
            relative = str(file_path.relative_to(root)).replace("\\", "/")
            data = file_path.read_bytes()
            signature[relative] = (len(data), hashlib.sha256(data).digest())
    return signature


class TestDirectoryIntake:
    def test_resolves_existing_directory(self, tmp_path: Path) -> None:
        project = tmp_path / "proj"
        project.mkdir()
        target = open_directory_target(project)
        assert target.target_path == project.resolve()
        assert target.temporary is False
        assert target.origin == str(project.resolve())

    def test_expands_home_marker(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("USERPROFILE", str(tmp_path))
        project = tmp_path / "homeproj"
        project.mkdir()
        target = open_directory_target("~/homeproj")
        assert target.target_path == project.resolve()

    def test_missing_path_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(TargetNotAvailableError, match="could not be resolved"):
            open_directory_target(tmp_path / "does-not-exist")

    def test_file_instead_of_directory_rejected(self, tmp_path: Path) -> None:
        file_path = tmp_path / "plain.txt"
        file_path.write_text("x", encoding="utf-8")
        with pytest.raises(TargetNotAvailableError, match="existing directory"):
            open_directory_target(file_path)

    def test_collector_reads_validated_directory(self, tmp_path: Path) -> None:
        project = tmp_path / "proj"
        (project / "src").mkdir(parents=True)
        (project / "src" / "main.py").write_text("value = 1\n", encoding="utf-8")
        target = open_directory_target(project)
        collected = WorkspaceCollector(AgentConfig()).collect(target.target_path)
        assert [item.relative_path for item in collected.files] == ["src/main.py"]

    def test_original_directory_unchanged_by_intake_and_collection(self, tmp_path: Path) -> None:
        project = tmp_path / "proj"
        project.mkdir()
        (project / "app.py").write_text("print('hi')\n", encoding="utf-8")
        before = _tree_signature(project)

        target = open_directory_target(project)
        collector = WorkspaceCollector(AgentConfig())
        collector.collect(target.target_path)

        assert _tree_signature(project) == before


class TestZipIntakeHappyPath:
    def test_extracts_flat_archive_into_disposable_dir(self, tmp_path: Path) -> None:
        archive = tmp_path / "proj.zip"
        _make_zip(archive, {"main.py": b"value = 1\n", "docs/readme.md": b"# hi\n"})
        with open_zip_target(archive, work_root=tmp_path / "work") as intake:
            assert intake.temporary is True
            extracted = intake.target_path
            assert (extracted / "main.py").read_bytes() == b"value = 1\n"
            assert (extracted / "docs" / "readme.md").read_bytes() == b"# hi\n"

    def test_single_top_level_folder_is_unwrapped(self, tmp_path: Path) -> None:
        archive = tmp_path / "wrapped.zip"
        _make_zip(
            archive,
            {
                "my-project/app.py": b"pass\n",
                "my-project/lib/util.py": b"x = 1\n",
            },
        )
        with open_zip_target(archive, work_root=tmp_path / "work") as intake:
            assert intake.target_path.name == "my-project"
            assert (intake.target_path / "lib" / "util.py").is_file()

    def test_multiple_roots_keep_extraction_dir_as_root(self, tmp_path: Path) -> None:
        archive = tmp_path / "multi.zip"
        _make_zip(archive, {"a.py": b"a = 1\n", "b/b.py": b"b = 2\n"})
        with open_zip_target(archive, work_root=tmp_path / "work") as intake:
            assert (intake.target_path / "a.py").is_file()
            assert (intake.target_path / "b" / "b.py").is_file()

    def test_extracted_tree_feeds_workspace_collector(self, tmp_path: Path) -> None:
        archive = tmp_path / "scanme.zip"
        _make_zip(archive, {"svc/app.py": b"import flask\n", "svc/notes.txt": b"nope\n"})
        with open_zip_target(archive, work_root=tmp_path / "work") as intake:
            collected = WorkspaceCollector(AgentConfig()).collect(intake.target_path)
            assert [item.relative_path for item in collected.files] == [
                "app.py",
                "notes.txt",
            ]

    def test_temporary_tree_removed_after_context_exit(self, tmp_path: Path) -> None:
        archive = tmp_path / "gone.zip"
        _make_zip(archive, {"x.py": b"x = 1\n"})
        holder = open_zip_target(archive, work_root=tmp_path / "work")
        with holder as intake:
            extracted = intake.target_path
            assert extracted.is_dir()
        assert not extracted.exists()

    def test_user_directory_never_deleted_on_exit(self, tmp_path: Path) -> None:
        project = tmp_path / "real"
        project.mkdir()
        holder = DisposableIntake(open_directory_target(project))
        with holder as intake:
            assert intake.temporary is False
        assert project.is_dir()


class TestZipSlipAndUnsafeMembers:
    @pytest.mark.parametrize(
        ("member_name", "reason"),
        [
            ("../escaped.txt", "escapes the extraction directory"),
            ("a/../../escaped.txt", "escapes the extraction directory"),
            ("/etc/passwd", "absolute path"),
            ("C:/evil.py", "drive-letter"),
            ("C:\\evil.py", "drive-letter"),
            ("\\\\server\\share\\x.py", "absolute path"),
        ],
    )
    def test_traversal_members_rejected_before_writes(
        self, tmp_path: Path, member_name: str, reason: str
    ) -> None:
        archive = tmp_path / "slip.zip"
        _make_zip(archive, {member_name: b"evil\n"})
        with pytest.raises(ArchiveRejectedError, match=reason):
            holder = open_zip_target(archive, work_root=tmp_path / "work")
            with holder:
                pass

    def test_symlink_member_rejected(self, tmp_path: Path) -> None:
        archive = tmp_path / "link.zip"
        info = zipfile.ZipInfo("link.py")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr(info, b"../../target")
        with pytest.raises(ArchiveRejectedError, match="symbolic link"):
            open_zip_target(archive, work_root=tmp_path / "work")

    def test_nothing_written_when_screening_fails(self, tmp_path: Path) -> None:
        work = tmp_path / "work"
        archive = tmp_path / "slip.zip"
        _make_zip(archive, {"ok.py": b"ok = 1\n", "../evil.txt": b"evil\n"})
        with pytest.raises(ArchiveRejectedError):
            open_zip_target(archive, work_root=work)
        # No temp tree may survive a failed extraction.
        survivors = list(work.glob("mugiwara-intake-*")) if work.is_dir() else []
        assert survivors == []


class TestExtractionLimits:
    def test_entry_count_cap(self, tmp_path: Path) -> None:
        archive = tmp_path / "many.zip"
        _make_zip(archive, {f"f{index}.py": b"x = 1\n" for index in range(5)})
        limits = IntakeLimits(max_entries=3)
        with pytest.raises(ArchiveRejectedError, match="exceeds the limit of 3"):
            open_zip_target(archive, work_root=tmp_path / "work", limits=limits)

    def test_total_size_cap(self, tmp_path: Path) -> None:
        archive = tmp_path / "big.zip"
        _make_zip(archive, {"a.py": b"a" * 100, "b.py": b"b" * 100})
        limits = IntakeLimits(max_total_bytes=150)
        with pytest.raises(ArchiveRejectedError, match="total size limit"):
            open_zip_target(archive, work_root=tmp_path / "work", limits=limits)

    def test_member_size_cap_declared(self, tmp_path: Path) -> None:
        archive = tmp_path / "fat.zip"
        _make_zip(archive, {"huge.py": b"h" * 500, "tiny.py": b"t\n"})
        limits = IntakeLimits(max_member_bytes=100)
        with pytest.raises(ArchiveRejectedError, match="per-file limit"):
            open_zip_target(archive, work_root=tmp_path / "work", limits=limits)

    def test_streaming_overrun_detected_for_lying_header(self, tmp_path: Path) -> None:
        archive = tmp_path / "lie.zip"
        payload = b"L" * 4096
        _make_zip(archive, {"liar.py": payload})
        # Rewrite the declared size so screening sees a small member but the
        # stream produces far more bytes.
        forged = io.BytesIO()
        with zipfile.ZipFile(archive) as source, zipfile.ZipFile(forged, "w") as target:
            for info in source.infolist():
                data = source.read(info.filename)
                lying = zipfile.ZipInfo(info.filename)
                lying.file_size = 4
                lying.compress_type = zipfile.ZIP_STORED
                target.writestr(lying, data)
        (tmp_path / "lie.zip").write_bytes(forged.getvalue())
        limits = IntakeLimits(max_member_bytes=1024)
        with pytest.raises(ArchiveRejectedError):
            holder = open_zip_target(
                tmp_path / "lie.zip", work_root=tmp_path / "work", limits=limits
            )
            with holder:
                pass


class _FakeZip(zipfile.ZipFile):
    """Minimal ZipFile stand-in exposing only infolist() for screener tests.

    Subclasses the real type so it satisfies ``_screen_archive``'s signature
    without ever touching the filesystem.
    """

    def __init__(self, infos: list[zipfile.ZipInfo]) -> None:
        self._infos = infos

    def infolist(self) -> list[zipfile.ZipInfo]:
        return self._infos


class TestUnsafeMemberScreening:
    def test_screen_rejects_encrypted_flag(self) -> None:
        info = zipfile.ZipInfo("secret.py")
        info.file_size = 4
        info.flag_bits |= 0x1
        with pytest.raises(ArchiveRejectedError, match="encrypted"):
            _screen_archive(_FakeZip([info]), IntakeLimits())

    def test_safe_member_name_rejects_nul_byte(self) -> None:
        with pytest.raises(ArchiveRejectedError, match="NUL"):
            _safe_member_name("bad\x00name.py")

    def test_screen_allows_permission_only_attrs(self) -> None:
        info = zipfile.ZipInfo("plain.py")
        info.external_attr = 0o600 << 16
        info.file_size = 10
        _screen_archive(_FakeZip([info]), IntakeLimits())


class TestMalformedArchives:
    def test_missing_zip_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(TargetNotAvailableError, match="not found"):
            open_zip_target(tmp_path / "nope.zip", work_root=tmp_path / "work")

    def test_non_zip_file_rejected(self, tmp_path: Path) -> None:
        fake = tmp_path / "fake.zip"
        fake.write_text("definitely not a zip", encoding="utf-8")
        with pytest.raises(ArchiveRejectedError, match="not a readable ZIP"):
            open_zip_target(fake, work_root=tmp_path / "work")

    def test_empty_archive_rejected(self, tmp_path: Path) -> None:
        archive = tmp_path / "empty.zip"
        with zipfile.ZipFile(archive, "w"):
            pass
        with pytest.raises(ArchiveRejectedError, match="no files"):
            open_zip_target(archive, work_root=tmp_path / "work")

    def test_directories_only_archive_rejected(self, tmp_path: Path) -> None:
        archive = tmp_path / "dirs.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            dir_info = zipfile.ZipInfo("only-dirs/")
            zf.writestr(dir_info, b"")
        with pytest.raises(ArchiveRejectedError, match="no files"):
            open_zip_target(archive, work_root=tmp_path / "work")


class TestLimitValidation:
    def test_non_positive_limits_rejected(self) -> None:
        with pytest.raises(ValueError, match="must be positive"):
            IntakeLimits(max_entries=0)
        with pytest.raises(ValueError, match="must be positive"):
            IntakeLimits(max_total_bytes=-1)
        with pytest.raises(ValueError, match="must be positive"):
            IntakeLimits(max_member_bytes=0)


class TestExceptionHierarchy:
    def test_intake_errors_are_mugiwara_errors(self) -> None:
        assert issubclass(IntakeError, MugiwaraError)
        assert issubclass(TargetNotAvailableError, IntakeError)
        assert issubclass(ArchiveRejectedError, IntakeError)
