"""Tests for S4 exporter/store consistency in 'mugiwara report export'."""

import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mugiwara.cli.main import app
from mugiwara.models.evidence import Evidence
from mugiwara.models.finding import Finding, FindingStatus, Severity, VulnerabilityCategory
from mugiwara.models.report import ScanReport
from mugiwara.providers.mock import MockLLMProvider
from mugiwara.reports.store import (
    ReportStore,
    ScanConfigurationSnapshot,
    TargetMetadata,
)

runner = CliRunner()

T0 = datetime(2026, 8, 20, 9, 0, 0, tzinfo=timezone.utc)

BENIGN_SOURCE = "value = 1\nprint(value)\n"

FINDING_SOURCE = "api_key = 'supersecret9'\nprint(api_key)\n"


def _finding(*, verified: bool) -> Finding:
    finding = Finding(
        title="Verified SQL injection",
        description="d",
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        status=FindingStatus.VERIFIED if verified else FindingStatus.SUSPECTED,
        evidence=(
            Evidence(
                poc_script="probe = '1 OR 1=1'",
                reproduction_steps=["send payload", "observe canary"],
                canary_found=True,
                canary_token="MUGI-CANARY",
                stdout_log="canary observed",
            )
            if verified
            else None
        ),
    )
    return finding


def _snapshot() -> ScanConfigurationSnapshot:
    return ScanConfigurationSnapshot(
        scan_profile="standard",
        llm_provider="mock",
        llm_model="m",
        sandbox_mode="mock",
        verification_enabled=True,
        include_evidence=True,
    )


def _seed(store_root: Path, *, verified: bool = True) -> str:
    store = ReportStore(root=store_root)
    report = ScanReport(target_path="demo-app", findings=[_finding(verified=verified)])
    report.calculate_summary()
    envelope = store.save(
        report,
        target=TargetMetadata(path="demo-app", origin="directory"),
        configuration=_snapshot(),
        now=T0,
    )
    return envelope.report_id


# -- evidence inclusion ------------------------------------------------------


@pytest.fixture()
def seeded_store(tmp_path: Path) -> tuple[Path, str]:
    store_root = tmp_path / "reports"
    report_id = _seed(store_root, verified=True)
    return store_root, report_id


def test_sarif_includes_evidence_by_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    seeded_store: tuple[Path, str],
) -> None:
    store_root, report_id = seeded_store
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "with.sarif"

    result = runner.invoke(
        app,
        [
            "report",
            "export",
            report_id,
            "--format",
            "sarif",
            "--output",
            str(out),
            "--store",
            str(store_root),
        ],
    )

    assert result.exit_code == 0, result.stdout
    document = json.loads(out.read_text(encoding="utf-8"))
    properties = document["runs"][0]["results"][0]["properties"]
    assert "mugiwara:evidence" in properties
    assert properties["mugiwara:evidence"]["canaryToken"] == "MUGI-CANARY"


def test_sarif_omits_evidence_when_disabled_via_cli(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    seeded_store: tuple[Path, str],
) -> None:
    store_root, report_id = seeded_store
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "without.sarif"

    result = runner.invoke(
        app,
        [
            "report",
            "export",
            report_id,
            "--format",
            "sarif",
            "--output",
            str(out),
            "--no-include-evidence",
            "--store",
            str(store_root),
        ],
    )

    assert result.exit_code == 0, result.stdout
    document = json.loads(out.read_text(encoding="utf-8"))
    properties = document["runs"][0]["results"][0]["properties"]
    assert "mugiwara:evidence" not in properties


def test_configured_include_evidence_false_is_honored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    seeded_store: tuple[Path, str],
) -> None:
    store_root, report_id = seeded_store
    monkeypatch.chdir(tmp_path)
    (tmp_path / "mugiwara.yaml").write_text(
        "output:\n  include_evidence: false\n", encoding="utf-8"
    )
    out = tmp_path / "configured-off.sarif"

    result = runner.invoke(
        app,
        ["report", "export", report_id, "-f", "sarif", "-o", str(out), "--store", str(store_root)],
    )

    assert result.exit_code == 0, result.stdout
    document = json.loads(out.read_text(encoding="utf-8"))
    assert "mugiwara:evidence" not in document["runs"][0]["results"][0]["properties"]


def test_cli_flag_overrides_configured_evidence_setting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    seeded_store: tuple[Path, str],
) -> None:
    store_root, report_id = seeded_store
    monkeypatch.chdir(tmp_path)
    (tmp_path / "mugiwara.yaml").write_text(
        "output:\n  include_evidence: false\n", encoding="utf-8"
    )
    out = tmp_path / "forced-on.sarif"

    result = runner.invoke(
        app,
        [
            "report",
            "export",
            report_id,
            "-f",
            "sarif",
            "-o",
            str(out),
            "--include-evidence",
            "--store",
            str(store_root),
        ],
    )

    assert result.exit_code == 0, result.stdout
    document = json.loads(out.read_text(encoding="utf-8"))
    assert "mugiwara:evidence" in document["runs"][0]["results"][0]["properties"]


def test_json_export_strips_evidence_when_excluded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    seeded_store: tuple[Path, str],
) -> None:
    store_root, report_id = seeded_store
    monkeypatch.chdir(tmp_path)

    kept = tmp_path / "kept.json"
    stripped = tmp_path / "stripped.json"
    for destination, flag in ((kept, []), (stripped, ["--no-include-evidence"])):
        result = runner.invoke(
            app,
            [
                "report",
                "export",
                report_id,
                "-f",
                "json",
                "-o",
                str(destination),
                "--store",
                str(store_root),
                *flag,
            ],
        )
        assert result.exit_code == 0, result.stdout

    kept_document = json.loads(kept.read_text(encoding="utf-8"))
    stripped_document = json.loads(stripped.read_text(encoding="utf-8"))
    assert kept_document["schema"] == "mugiwara.scan-report"
    assert kept_document["scan"]["findings"][0].get("evidence") is not None
    assert stripped_document["schema"] == "mugiwara.scan-report"
    assert stripped_document["scan"]["findings"][0].get("evidence") is None
    assert stripped_document["report_id"] == report_id


# -- deterministic default names ---------------------------------------------


def test_default_filenames_contain_the_report_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    seeded_store: tuple[Path, str],
) -> None:
    store_root, report_id = seeded_store
    monkeypatch.chdir(tmp_path)

    for export_format, suffix in (("json", ".json"), ("sarif", ".sarif"), ("markdown", ".md")):
        result = runner.invoke(
            app,
            [
                "report",
                "export",
                report_id,
                "-f",
                export_format,
                "--store",
                str(store_root),
            ],
        )
        expected = tmp_path / f"report-{report_id}{suffix}"
        assert result.exit_code == 0, result.stdout
        assert expected.exists(), result.stdout
        assert f"{expected.name}" in result.stdout


def test_explicit_output_path_wins_and_overwrites(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    seeded_store: tuple[Path, str],
) -> None:
    store_root, report_id = seeded_store
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "explicit.sarif"

    first = runner.invoke(
        app,
        ["report", "export", report_id, "-f", "sarif", "-o", str(out), "--store", str(store_root)],
    )
    second = runner.invoke(
        app,
        ["report", "export", report_id, "-f", "sarif", "-o", str(out), "--store", str(store_root)],
    )

    assert first.exit_code == 0, first.stdout
    assert second.exit_code == 0, second.stdout
    assert out.is_file()
    assert not (tmp_path / "explicit-2.sarif").exists()


def test_default_name_collision_never_overwrites(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    seeded_store: tuple[Path, str],
) -> None:
    store_root, report_id = seeded_store
    monkeypatch.chdir(tmp_path)
    original = tmp_path / f"report-{report_id}.sarif"
    original.write_text("sentinel-content", encoding="utf-8")

    result = runner.invoke(
        app,
        ["report", "export", report_id, "-f", "sarif", "--store", str(store_root)],
    )

    assert result.exit_code == 0, result.stdout
    assert original.read_text(encoding="utf-8") == "sentinel-content"
    bumped = tmp_path / f"report-{report_id}-2.sarif"
    assert bumped.is_file()
    assert "sentinel-content" not in bumped.read_text(encoding="utf-8")


# -- store resolution precedence ---------------------------------------------


def test_explicit_store_beats_configured_reports_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    explicit_root = tmp_path / "explicit-store"
    configured_root = tmp_path / "configured-store"
    explicit_id = _seed(explicit_root, verified=False)
    _seed(configured_root, verified=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "mugiwara.yaml").write_text(
        f"output:\n  reports_dir: {configured_root.as_posix()}\n", encoding="utf-8"
    )

    result = runner.invoke(
        app,
        ["report", "export", explicit_id, "-f", "sarif", "--store", str(explicit_root)],
    )

    assert result.exit_code == 0, result.stdout
    assert (tmp_path / f"report-{explicit_id}.sarif").is_file()


def test_configured_reports_dir_beats_target_anchor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured_root = tmp_path / "configured-archive"
    _seed(configured_root, verified=False)
    proj = tmp_path / "proj"
    local_id = _seed(proj / ".mugiwara" / "reports", verified=False)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "mugiwara.yaml").write_text(
        f"output:\n  reports_dir: {configured_root.as_posix()}\n", encoding="utf-8"
    )
    monkeypatch.chdir(elsewhere)

    result = runner.invoke(
        app,
        ["report", "export", local_id, "-f", "sarif", "--target", str(proj)],
    )

    assert result.exit_code == 1
    assert "not found" in result.stderr.lower()


def test_directory_target_anchor_resolves_for_export(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proj = tmp_path / "proj"
    store_root = proj / ".mugiwara" / "reports"
    report_id = _seed(store_root, verified=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    result = runner.invoke(
        app,
        ["report", "export", report_id, "-f", "markdown", "--target", str(proj)],
    )

    assert result.exit_code == 0, result.stdout
    exported = (tmp_path / "elsewhere" / f"report-{report_id}.md").read_text(encoding="utf-8")
    assert "### Verification evidence" in exported


# -- directory + ZIP persisted reports ----------------------------------------


def test_zip_persisted_report_exports_after_extraction_deleted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    watch = tmp_path / "tempwatch"
    watch.mkdir()
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(watch))
    monkeypatch.setattr(
        "mugiwara.agents.orchestrator.get_provider", lambda _config: MockLLMProvider()
    )
    monkeypatch.chdir(tmp_path)
    project_src = tmp_path / "src"
    project_src.mkdir()
    (project_src / "app.py").write_text(FINDING_SOURCE, encoding="utf-8")
    archive = tmp_path / "demo.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("demo/app.py", FINDING_SOURCE)

    scanned = runner.invoke(
        app,
        ["scan", str(archive), "--provider", "mock", "--sandbox", "mock"],
        env={"COLUMNS": "200"},
    )
    assert scanned.exit_code == 2, scanned.stdout
    assert list(watch.glob("mugiwara-intake-*")) == []

    store_root = tmp_path / ".mugiwara" / "reports"
    documents = sorted(store_root.glob("*.json"))
    assert len(documents) == 1
    report_id = documents[0].stem

    exported = runner.invoke(
        app,
        ["report", "export", report_id, "-f", "sarif", "--store", str(store_root)],
    )

    assert exported.exit_code == 0, exported.stdout
    document = json.loads((tmp_path / f"report-{report_id}.sarif").read_text(encoding="utf-8"))
    run_properties = document["runs"][0]["properties"]
    assert run_properties["mugiwara:targetPath"].endswith("demo.zip")
    assert len(document["runs"][0]["results"]) == 1


# -- fail-closed references ----------------------------------------------------


def test_unknown_reference_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    seeded_store: tuple[Path, str],
) -> None:
    store_root, _ = seeded_store
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        [
            "report",
            "export",
            "20990101T000000-deadbeef00",
            "-f",
            "sarif",
            "--store",
            str(store_root),
        ],
    )

    assert result.exit_code == 1
    assert "not found" in result.stderr.lower()


def test_traversal_reference_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    seeded_store: tuple[Path, str],
) -> None:
    store_root, _ = seeded_store
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        ["report", "export", "../../escape.json", "-f", "sarif", "--store", str(store_root)],
    )

    assert result.exit_code == 1
    assert "escapes the report store" in result.stderr


def test_malformed_stored_document_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    seeded_store: tuple[Path, str],
) -> None:
    store_root, report_id = seeded_store
    (store_root / f"{report_id}.json").write_text("{broken", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        ["report", "export", report_id, "-f", "sarif", "--store", str(store_root)],
    )

    assert result.exit_code == 1
    assert "not valid JSON" in result.stderr
