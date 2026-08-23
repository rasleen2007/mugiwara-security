"""Tests for 'mugiwara report list/delete' and shared store-root resolution."""

import re
from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mugiwara.cli.main import app
from mugiwara.models.finding import Finding, FindingStatus, Severity, VulnerabilityCategory
from mugiwara.models.report import ScanReport
from mugiwara.reports.store import (
    ReportStore,
    ScanConfigurationSnapshot,
    TargetMetadata,
)

runner = CliRunner()

# Rich defaults to an 80-column console when stdout is captured, truncating
# report IDs with an ellipsis. Widen the capture so full rows are asserted.
WIDE_ENV = {"COLUMNS": "200"}


def _invoke(args: list[str], **kwargs):
    return runner.invoke(app, args, env=WIDE_ENV, **kwargs)


T0 = datetime(2026, 8, 20, 9, 0, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 8, 21, 9, 0, 0, tzinfo=timezone.utc)
T2 = datetime(2026, 8, 22, 9, 0, 0, tzinfo=timezone.utc)


def _finding(status: FindingStatus = FindingStatus.SUSPECTED) -> Finding:
    return Finding(
        title=f"Finding {status.value}",
        description="d",
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        status=status,
    )


def _report(target_path: str, findings: list[Finding]) -> ScanReport:
    report = ScanReport(target_path=target_path, findings=findings)
    report.calculate_summary()
    return report


def _snapshot() -> ScanConfigurationSnapshot:
    return ScanConfigurationSnapshot(
        scan_profile="standard",
        llm_provider="mock",
        llm_model="m",
        sandbox_mode="mock",
        verification_enabled=False,
        include_evidence=True,
    )


def _seed(store_root: Path, findings: list[Finding], when: datetime) -> str:
    store = ReportStore(root=store_root)
    envelope = store.save(
        _report("demo-app", findings),
        target=TargetMetadata(path="demo-app", origin="directory"),
        configuration=_snapshot(),
        now=when,
    )
    return envelope.report_id


# -- report list ----------------------------------------------------------------------


def test_list_empty_store_prints_friendly_message(tmp_path: Path) -> None:
    result = _invoke(["report", "list", "--store", str(tmp_path / "fresh")])

    assert result.exit_code == 0
    assert "No persisted reports" in result.stdout


def test_list_multiple_reports_newest_first(tmp_path: Path) -> None:
    store_root = tmp_path / "reports"
    old = _seed(store_root, [_finding()], T0)
    middle = _seed(store_root, [_finding()], T1)
    newest = _seed(store_root, [_finding()], T2)

    result = _invoke(["report", "list", "--store", str(store_root)])

    assert result.exit_code == 0
    for report_id in (old, middle, newest):
        assert report_id in result.stdout
    order = [result.stdout.index(report_id) for report_id in (newest, middle, old)]
    assert order == sorted(order)


def test_list_shows_counts_and_target(tmp_path: Path) -> None:
    store_root = tmp_path / "reports"
    report_id = _seed(
        store_root,
        [_finding(), _finding(FindingStatus.VERIFIED), _finding()],
        T0,
    )

    result = _invoke(["report", "list", "--store", str(store_root)])
    row = next(line for line in result.stdout.splitlines() if report_id in line)

    assert result.exit_code == 0
    assert "demo-app" in row
    for count in ("3", "1", "2"):
        assert re.search(rf"[│|]\s*{count}\s*[│|]", row)


def test_list_resolves_target_local_store(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    store_root = proj / ".mugiwara" / "reports"
    report_id = _seed(store_root, [_finding()], T0)

    result = _invoke(["report", "list", "--target", str(proj)])

    assert result.exit_code == 0
    assert report_id in result.stdout


def test_configured_reports_dir_outranks_target_anchor(
    tmp_path: Path,
) -> None:
    configured = tmp_path / "configured-archive"
    configured_id = _seed(configured, [_finding()], T0)
    proj = tmp_path / "proj"
    local_id = _seed(proj / ".mugiwara" / "reports", [_finding()], T1)
    config_file = tmp_path / "mugiwara.yaml"
    config_file.write_text(f"output:\n  reports_dir: {configured.as_posix()}\n", encoding="utf-8")

    result = _invoke(["report", "list", "--target", str(proj), "--config-file", str(config_file)])

    assert result.exit_code == 0
    assert configured_id in result.stdout
    assert local_id not in result.stdout


def test_show_uses_target_local_store_without_override(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    store_root = proj / ".mugiwara" / "reports"
    report_id = _seed(store_root, [_finding()], T0)

    result = _invoke(["report", "show", report_id, "--target", str(proj)])

    assert result.exit_code == 0
    assert "# Mugiwara Security Report" in result.stdout


# -- report delete ----------------------------------------------------------------------


def test_delete_requires_confirmation(tmp_path: Path) -> None:
    store_root = tmp_path / "reports"
    report_id = _seed(store_root, [_finding()], T0)

    result = runner.invoke(
        app,
        ["report", "delete", report_id, "--store", str(store_root)],
        input="n\n",
    )

    assert result.exit_code == 1
    assert "Permanently delete" in result.stdout
    assert (store_root / f"{report_id}.json").is_file()


def test_delete_yes_succeeds_non_interactively(tmp_path: Path) -> None:
    store_root = tmp_path / "reports"
    report_id = _seed(store_root, [_finding()], T0)

    result = runner.invoke(
        app,
        ["report", "delete", report_id, "--yes", "--store", str(store_root)],
    )

    assert result.exit_code == 0
    assert "Deleted report" in result.stdout
    assert not (store_root / f"{report_id}.json").exists()


def test_delete_unknown_report_fails_cleanly(tmp_path: Path) -> None:
    store_root = tmp_path / "reports"

    result = runner.invoke(
        app,
        [
            "report",
            "delete",
            "20990101T000000-deadbeef00",
            "--yes",
            "--store",
            str(store_root),
        ],
    )

    assert result.exit_code == 1
    assert "not found" in result.stdout.lower()


def test_delete_traversal_reference_is_rejected(tmp_path: Path) -> None:
    store_root = tmp_path / "reports"

    result = runner.invoke(
        app,
        ["report", "delete", "../../escape.json", "--yes", "--store", str(store_root)],
    )

    assert result.exit_code == 1
    assert "escapes the report store" in result.stdout


@pytest.mark.parametrize("command", ["list", "delete"])
def test_subcommands_are_registered(command: str) -> None:
    result = runner.invoke(app, ["report", command, "--help"])

    assert result.exit_code == 0
