"""Tests for S3 ZIP intake wiring: 'mugiwara scan <archive>.zip'.

All scans run through the real hardened intake layer and the mock
provider/sandbox; temporary extraction roots are redirected into a watched
directory so their lifecycle can be audited.
"""

import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mugiwara.cli.main import app
from mugiwara.core.exceptions import MugiwaraError
from mugiwara.exporters.markdown import export_report_to_markdown
from mugiwara.providers.mock import MockLLMProvider
from mugiwara.reports.store import ReportStore

runner = CliRunner()

# Rich defaults to an 80-column console when stdout is captured, truncating
# long target paths. Widen the capture so full rows are asserted.
WIDE_ENV = {"COLUMNS": "200"}

BENIGN_SOURCE = "value = 1\nprint(value)\n"

FINDING_SOURCE = "api_key = 'supersecret9'\nprint(api_key)\n"


def _make_zip(path: Path, members: dict[str, str]) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, payload in members.items():
            zf.writestr(name, payload)


@pytest.fixture(autouse=True)
def _mock_backends(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "mugiwara.agents.orchestrator.get_provider", lambda _config: MockLLMProvider()
    )


@pytest.fixture
def temp_watch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect platform temp storage to a watched, empty directory."""
    watch = tmp_path / "tempwatch"
    watch.mkdir()
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(watch))
    return watch


def _invoke(target: Path | str, *extra: str):
    return runner.invoke(
        app,
        ["scan", str(target), "--provider", "mock", "--sandbox", "mock", *extra],
        env=WIDE_ENV,
    )


def test_zip_scan_succeeds_and_cleans_up(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    temp_watch: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    archive = tmp_path / "demo.zip"
    _make_zip(archive, {"demo/main.py": BENIGN_SOURCE})

    result = _invoke(archive)

    assert result.exit_code == 0, result.stdout
    assert "Mugiwara Scan Summary" in result.stdout
    # The summary must describe the durable archive, never a temp path.
    assert str(archive) in result.stdout
    assert "mugiwara-intake-" not in result.stdout.replace(str(temp_watch), "")
    assert "Scan completed cleanly" in result.stdout
    assert list(temp_watch.glob("mugiwara-intake-*")) == []


def test_zip_scan_persists_report_bound_to_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    temp_watch: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    archive = tmp_path / "demo.zip"
    _make_zip(archive, {"demo/main.py": FINDING_SOURCE})

    result = _invoke(archive)

    assert result.exit_code == 2, result.stdout
    store_root = tmp_path / ".mugiwara" / "reports"
    documents = sorted(store_root.glob("*.json"))
    assert len(documents) == 1

    envelope = ReportStore(store_root).load(documents[0].stem)
    assert envelope.target.origin == "archive"
    assert envelope.target.path == str(archive)
    assert envelope.scan.target_path == str(archive)
    assert len(envelope.scan.findings) == 1
    assert envelope.scan.findings[0].location.file_path == "main.py"
    assert not any("mugiwara-intake-" in part.name for part in temp_watch.iterdir())


def test_failed_zip_scan_still_cleans_extraction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    temp_watch: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    archive = tmp_path / "demo.zip"
    _make_zip(archive, {"main.py": BENIGN_SOURCE})

    def exploding(_settings, target_override=None):
        raise MugiwaraError("simulated orchestrator crash")

    monkeypatch.setattr("mugiwara.agents.orchestrator.run_scan", exploding)

    result = _invoke(archive)

    assert result.exit_code == 1
    assert "Scan failed" in result.stdout
    assert list(temp_watch.glob("mugiwara-intake-*")) == []


def test_directory_scan_regression_no_intake_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    temp_watch: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    root = tmp_path / "proj"
    root.mkdir()
    (root / "main.py").write_text(BENIGN_SOURCE, encoding="utf-8")

    result = _invoke(root)

    assert result.exit_code == 0, result.stdout
    documents = sorted((root / ".mugiwara" / "reports").glob("*.json"))
    assert len(documents) == 1
    envelope = ReportStore(root / ".mugiwara" / "reports").load(documents[0].stem)
    assert envelope.target.origin == "directory"
    assert envelope.target.path == str(root.resolve())
    assert list(temp_watch.glob("*")) == []


def test_traversal_archive_rejected_with_no_residue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    temp_watch: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../escape.txt", b"x")
        zf.writestr("main.py", BENIGN_SOURCE)

    result = _invoke(archive)

    assert result.exit_code == 1
    assert "ZIP target rejected" in result.stdout
    assert "escapes the extraction directory" in result.stdout
    assert list(temp_watch.glob("mugiwara-intake-*")) == []


def test_malformed_archive_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    temp_watch: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    archive = tmp_path / "broken.zip"
    archive.write_bytes(b"PK\x03\x04 this is not really a zip")

    result = _invoke(archive)

    assert result.exit_code == 1
    assert "not a readable ZIP archive" in result.stdout
    assert list(temp_watch.glob("mugiwara-intake-*")) == []


def test_entry_limit_violation_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    temp_watch: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    archive = tmp_path / "many.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_STORED) as zf:
        for index in range(5001):
            zf.writestr(f"payload/{index}.txt", "x")

    result = _invoke(archive)

    assert result.exit_code == 1
    assert "exceeds the limit" in result.stdout
    assert list(temp_watch.glob("mugiwara-intake-*")) == []


def test_url_targets_are_not_supported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        ["scan", "https://example.invalid/app.zip", "--provider", "mock"],
    )

    assert result.exit_code == 1
    assert "ZIP archive not found" in result.stdout


def test_scan_help_does_not_claim_url_support() -> None:
    result = runner.invoke(app, ["scan", "--help"])

    assert result.exit_code == 0
    assert "URL" not in result.stdout
    assert ".zip" in result.stdout


def test_persisted_zip_report_usable_after_extraction_deleted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    temp_watch: Path,
) -> None:
    """The stored envelope stays fully inspectable once its temp tree is gone."""
    monkeypatch.chdir(tmp_path)
    archive = tmp_path / "demo.zip"
    _make_zip(archive, {"demo/app.py": FINDING_SOURCE})

    result = _invoke(archive)
    assert result.exit_code == 2, result.stdout

    store_root = tmp_path / ".mugiwara" / "reports"
    document = next(iter(sorted(store_root.glob("*.json"))))
    envelope = ReportStore(store_root).load(document.stem)

    assert envelope.target.path == str(archive)
    markdown = export_report_to_markdown(envelope.scan)
    assert str(archive) in markdown
    assert "app.py" in markdown
    assert "mugiwara-intake-" not in markdown


def test_nested_zip_findings_survive_single_top_level_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    temp_watch: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    archive = tmp_path / "wrapped.zip"
    _make_zip(archive, {"src/demo/main.py": BENIGN_SOURCE, "src/demo/util.py": BENIGN_SOURCE})

    result = _invoke(archive)

    assert result.exit_code == 0, result.stdout
    assert list(temp_watch.glob("mugiwara-intake-*")) == []
