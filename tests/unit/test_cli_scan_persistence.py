"""Tests for S1 scan persistence wiring: successful scans archive reports.

All scans run against tmp targets with the mock provider/sandbox; the
report store is exercised through its real implementation.
"""

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mugiwara.cli.main import app
from mugiwara.core.exceptions import ReportStoreError
from mugiwara.providers.mock import MockLLMProvider
from mugiwara.reports.store import ReportStore

runner = CliRunner()

BENIGN_SOURCE = "value = 1\nprint(value)\n"

FINDING_SOURCE = "api_key = 'supersecret9'\nprint(api_key)\n"


def _make_target(tmp_path: Path, source: str, name: str = "proj") -> Path:
    root = tmp_path / name
    root.mkdir()
    (root / "main.py").write_text(source, encoding="utf-8")
    return root


@pytest.fixture(autouse=True)
def _mock_backends(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "mugiwara.agents.orchestrator.get_provider", lambda _config: MockLLMProvider()
    )


def _invoke_scan(target: Path, *extra: str):
    result = runner.invoke(
        app,
        ["scan", str(target), "--provider", "mock", "--sandbox", "mock", *extra],
    )
    assert result.exit_code in (0, 2), result.stdout
    return result


def _files_collected(stdout: str) -> int:
    matches = re.findall(r"Files Collected\s*[|│]\s*(\d+)", stdout)
    assert matches, stdout
    return int(matches[-1])


def test_normal_scan_saves_exactly_one_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    root = _make_target(tmp_path, BENIGN_SOURCE)

    result = _invoke_scan(root)

    assert result.exit_code == 0
    reports = sorted((root / ".mugiwara" / "reports").glob("*.json"))
    assert len(reports) == 1
    assert reports[0].stem in result.stdout
    assert "persisted" in result.stdout
    assert "Scan completed cleanly" in result.stdout


def test_dry_run_never_persists(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    root = _make_target(tmp_path, BENIGN_SOURCE)

    result = runner.invoke(app, ["scan", str(root), "--dry-run"])

    assert result.exit_code == 0
    assert not (root / ".mugiwara").exists()


def test_no_save_report_opt_out_persists_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    root = _make_target(tmp_path, BENIGN_SOURCE)

    result = _invoke_scan(root, "--no-save-report")

    assert result.exit_code == 0
    assert not (root / ".mugiwara").exists()
    assert "persisted" not in result.stdout


def test_configured_reports_dir_is_honored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    custom_root = tmp_path / "custom-archive"
    monkeypatch.chdir(tmp_path)
    (tmp_path / "mugiwara.yaml").write_text(
        f"output:\n  reports_dir: {custom_root.as_posix()}\n", encoding="utf-8"
    )
    root = _make_target(tmp_path, BENIGN_SOURCE)

    result = _invoke_scan(root)

    assert result.exit_code == 0
    assert len(list(custom_root.glob("*.json"))) == 1
    assert not (root / ".mugiwara" / "reports").exists()


def test_saved_report_loads_through_the_real_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    root = _make_target(tmp_path, FINDING_SOURCE)

    result = _invoke_scan(root)

    assert result.exit_code == 2, result.stdout
    store_root = root / ".mugiwara" / "reports"
    documents = list(store_root.glob("*.json"))
    assert len(documents) == 1

    envelope = ReportStore(store_root).load(documents[0].stem)
    assert envelope.target.path == str(root)
    assert envelope.configuration.llm_provider == "mock"
    assert envelope.target.files_collected >= 1
    assert len(envelope.scan.findings) == 1

    summary = envelope.scan.summary
    assert summary.total_findings == len(envelope.scan.findings)
    assert summary.suspected_count == 1
    assert summary.high_count == 1
    assert summary.verified_count == 0


def test_rescan_does_not_collect_archived_reports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The persisted .mugiwara tree must stay invisible to source collection."""
    monkeypatch.chdir(tmp_path)
    root = _make_target(tmp_path, BENIGN_SOURCE)

    first = _invoke_scan(root)
    second = _invoke_scan(root)

    assert _files_collected(first.stdout) == _files_collected(second.stdout)
    reports = list((root / ".mugiwara" / "reports").glob("*.json"))
    assert len(reports) == 2


def test_persistence_failure_warns_and_preserves_scan_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    root = _make_target(tmp_path, BENIGN_SOURCE)

    class ExplodingStore:
        def __init__(self, _root: Path) -> None:
            raise ReportStoreError("simulated store outage")

    monkeypatch.setattr("mugiwara.cli.commands.scan.ReportStore", ExplodingStore)

    result = _invoke_scan(root)

    assert result.exit_code == 0
    assert "could not be persisted" in result.stderr
    assert "Mugiwara Scan Summary" in result.stdout
    assert "Scan completed cleanly" in result.stdout
