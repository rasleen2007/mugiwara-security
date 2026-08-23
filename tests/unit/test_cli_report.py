"""Unit tests for the 'mugiwara report' CLI commands."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from mugiwara.cli.main import app
from mugiwara.models.finding import (
    Finding,
    FindingStatus,
    Severity,
    SourceLocation,
    VulnerabilityCategory,
)
from mugiwara.models.report import ScanReport
from mugiwara.reports.store import (
    SCHEMA_NAME,
    ReportStore,
    ScanConfigurationSnapshot,
    TargetMetadata,
)

runner = CliRunner()

MOMENT = datetime(2026, 8, 23, 9, 0, 0, tzinfo=timezone.utc)


def _finding(**overrides: Any) -> Finding:
    values: dict[str, Any] = {
        "title": "SQL injection in user lookup",
        "description": "Untrusted username reaches cursor.execute.",
        "category": VulnerabilityCategory.SQL_INJECTION,
        "severity": Severity.HIGH,
        "status": FindingStatus.VERIFIED,
        "location": SourceLocation(file_path="app.py", start_line=37, end_line=37),
    }
    values.update(overrides)
    return Finding(**values)


def _report() -> ScanReport:
    report = ScanReport(
        target_path=str(Path.cwd()),
        scan_profile="standard",
        findings=[_finding()],
    )
    report.calculate_summary()
    return report


def _seed_store(tmp_path: Path) -> tuple[Path, str]:
    store_root = tmp_path / ".mugiwara" / "reports"
    store = ReportStore(root=store_root)
    envelope = store.save(
        _report(),
        target=TargetMetadata(path="D:/work/demo-app", origin="directory: demo-app"),
        configuration=ScanConfigurationSnapshot(
            scan_profile="standard",
            llm_provider="mock",
            llm_model="mock-analyst",
            sandbox_mode="subprocess",
            verification_enabled=True,
            include_evidence=True,
        ),
        now=MOMENT,
    )
    return store_root, envelope.report_id


def test_show_renders_markdown_summary(tmp_path: Path) -> None:
    store_root, report_id = _seed_store(tmp_path)

    result = runner.invoke(app, ["report", "show", report_id, "--store", str(store_root)])

    assert result.exit_code == 0
    assert "# Mugiwara Security Report" in result.stdout
    assert "SQL injection in user lookup" in result.stdout
    assert f"| Status {FindingStatus.VERIFIED.value} | 1 |" in result.stdout


def test_show_missing_report_exits_one(tmp_path: Path) -> None:
    store_root, _ = _seed_store(tmp_path)

    result = runner.invoke(
        app, ["report", "show", "20990101T000000-deadbeef00", "--store", str(store_root)]
    )

    assert result.exit_code == 1
    assert "not found" in result.stdout.lower()


def test_show_path_traversal_reference_is_refused(tmp_path: Path) -> None:
    store_root, _ = _seed_store(tmp_path)

    result = runner.invoke(app, ["report", "show", "../../escape.json", "--store", str(store_root)])

    assert result.exit_code == 1
    assert "escapes the report store" in result.stdout


def test_show_malformed_file_fails_cleanly(tmp_path: Path) -> None:
    store_root, _ = _seed_store(tmp_path)
    (store_root / "20260823T090001-cafebabe01.json").write_text("{broken", encoding="utf-8")

    result = runner.invoke(
        app, ["report", "show", "20260823T090001-cafebabe01", "--store", str(store_root)]
    )

    assert result.exit_code == 1
    assert "not valid JSON" in result.stdout


def test_show_unsupported_schema_fails_cleanly(tmp_path: Path) -> None:
    store_root, _ = _seed_store(tmp_path)
    (store_root / "20260823T090002-cafebabe02.json").write_text(
        json.dumps({"schema": "other-tool.export", "schema_version": 3}),
        encoding="utf-8",
    )

    result = runner.invoke(
        app, ["report", "show", "20260823T090002-cafebabe02", "--store", str(store_root)]
    )

    assert result.exit_code == 1
    assert "Unsupported report schema" in result.stdout


def test_export_json_writes_full_envelope(tmp_path: Path) -> None:
    store_root, report_id = _seed_store(tmp_path)
    out = tmp_path / "out" / "envelope.json"

    result = runner.invoke(
        app,
        [
            "report",
            "export",
            report_id,
            "--format",
            "json",
            "--output",
            str(out),
            "--store",
            str(store_root),
        ],
    )

    assert result.exit_code == 0
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["schema"] == SCHEMA_NAME
    assert document["report_id"] == report_id
    assert document["scan"]["summary"]["total_findings"] == 1


def test_export_sarif_default_filename(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    store_root, report_id = _seed_store(tmp_path)

    result = runner.invoke(
        app,
        ["report", "export", report_id, "--format", "sarif", "--store", str(store_root)],
    )

    assert result.exit_code == 0
    exported = tmp_path / "report.sarif"
    assert exported.exists()
    document = json.loads(exported.read_text(encoding="utf-8"))
    assert document["version"] == "2.1.0"


def test_export_markdown_default_filename(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    store_root, report_id = _seed_store(tmp_path)

    result = runner.invoke(
        app,
        ["report", "export", report_id, "--format", "markdown", "--store", str(store_root)],
    )

    assert result.exit_code == 0
    exported = tmp_path / "report.md"
    content = exported.read_text(encoding="utf-8")
    assert "# Mugiwara Security Report" in content
    assert "Exported report" in result.stdout


def test_export_unknown_format_is_rejected_by_cli(tmp_path: Path) -> None:
    store_root, report_id = _seed_store(tmp_path)

    result = runner.invoke(
        app,
        [
            "report",
            "export",
            report_id,
            "--format",
            "html",
            "--store",
            str(store_root),
        ],
    )

    assert result.exit_code != 0


def test_configured_reports_dir_is_honored_without_store_override(
    tmp_path: Path,
) -> None:
    configured_root = tmp_path / "custom-reports"
    store = ReportStore(root=configured_root)
    envelope = store.save(
        _report(),
        target=TargetMetadata(path="D:/work/demo-app", origin="directory"),
        configuration=ScanConfigurationSnapshot(
            scan_profile="standard",
            llm_provider="mock",
            llm_model="m",
            sandbox_mode="subprocess",
            verification_enabled=False,
            include_evidence=False,
        ),
        now=MOMENT,
    )
    config_file = tmp_path / "mugiwara.yaml"
    config_file.write_text(
        f"output:\n  reports_dir: {configured_root.as_posix()}\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "report",
            "show",
            envelope.report_id,
            "--config-file",
            str(config_file),
        ],
    )

    assert result.exit_code == 0
    assert "# Mugiwara Security Report" in result.stdout


def test_export_reflects_authoritative_summary_not_stale_disk_values(
    tmp_path: Path,
) -> None:
    store_root, report_id = _seed_store(tmp_path)
    path = store_root / f"{report_id}.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    stale = document["scan"]["summary"]
    for key in stale:
        stale[key] = 999 if key.endswith("_count") or key == "total_findings" else stale[key]
    path.write_text(json.dumps(document), encoding="utf-8")

    out = tmp_path / "authoritative.json"
    result = runner.invoke(
        app,
        [
            "report",
            "export",
            report_id,
            "--format",
            "json",
            "--output",
            str(out),
            "--store",
            str(store_root),
        ],
    )

    assert result.exit_code == 0
    exported = json.loads(out.read_text(encoding="utf-8"))
    summary = exported["scan"]["summary"]
    assert summary["total_findings"] == 1
    assert summary["verified_count"] == 1
