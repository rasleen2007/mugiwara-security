"""Unit tests for the persisted scan-report store."""

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from mugiwara.core.config import LLMConfig, MugiwaraSettings, OutputConfig
from mugiwara.core.exceptions import (
    ReportFormatError,
    ReportInvalidContentsError,
    ReportNotFoundError,
    ReportPathEscapeError,
    UnsupportedSchemaError,
)
from mugiwara.models.evidence import Evidence
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
    SCHEMA_VERSION,
    ReportStore,
    ReportSummary,
    ScanConfigurationSnapshot,
    StoredScanReport,
    TargetMetadata,
    generate_report_id,
    resolve_report_root,
    snapshot_from_settings,
)

REPORT_ID_PATTERN = re.compile(r"^[0-9]{8}T[0-9]{6}-[0-9a-f]{10}$")

MOMENT = datetime(2026, 8, 23, 12, 30, 45, tzinfo=timezone.utc)


def _finding(**overrides: Any) -> Finding:
    values: dict[str, Any] = {
        "title": "SQL injection in user lookup",
        "description": "Untrusted username reaches cursor.execute.",
        "category": VulnerabilityCategory.SQL_INJECTION,
        "severity": Severity.HIGH,
        "status": FindingStatus.SUSPECTED,
        "location": SourceLocation(
            file_path="app/db.py",
            start_line=10,
            end_line=12,
        ),
    }
    values.update(overrides)
    return Finding(**values)


def _report(*findings: Finding) -> ScanReport:
    return ScanReport(
        target_path="D:/work/demo-app",
        scan_profile="standard",
        findings=list(findings) or [_finding(), _finding(status=FindingStatus.VERIFIED)],
    )


def _target() -> TargetMetadata:
    return TargetMetadata(
        path="D:/work/demo-app",
        origin="directory: D:/work/demo-app",
        files_collected=42,
        secret_markers_found=1,
    )


def _configuration() -> ScanConfigurationSnapshot:
    return ScanConfigurationSnapshot(
        scan_profile="standard",
        llm_provider="mock",
        llm_model="mock-analyst",
        sandbox_mode="subprocess",
        verification_enabled=True,
        include_evidence=True,
    )


@pytest.fixture()
def store(tmp_path: Path) -> ReportStore:
    return ReportStore(root=tmp_path / ".mugiwara" / "reports")


def _save_one(store: ReportStore, **kwargs: Any) -> StoredScanReport:
    return store.save(
        kwargs.pop("report", _report()),
        target=kwargs.pop("target", _target()),
        configuration=kwargs.pop("configuration", _configuration()),
        **kwargs,
    )


# -- save/load round trip --------------------------------------------------


def test_save_then_load_round_trips_envelope_and_scan(store: ReportStore) -> None:
    report = _report()
    original_dump = report.model_dump()
    saved = store.save(
        report,
        target=_target(),
        configuration=_configuration(),
        now=MOMENT,
    )

    loaded = store.load(saved.report_id)

    expected_scan = report.model_copy(deep=True)
    expected_scan.calculate_summary()

    assert loaded.schema_name == SCHEMA_NAME == "mugiwara.scan-report"
    assert loaded.schema_version == SCHEMA_VERSION == 1
    assert loaded.created_at == MOMENT
    assert loaded.target == _target()
    assert loaded.configuration == _configuration()
    assert loaded.scan.model_dump() == expected_scan.model_dump()
    # Saving must never mutate the caller's report object.
    assert report.model_dump() == original_dump


def test_saved_document_on_disk_carries_schema_marker(store: ReportStore) -> None:
    saved = _save_one(store, now=MOMENT)

    raw = json.loads((store.root / f"{saved.report_id}.json").read_text(encoding="utf-8"))

    assert raw["schema"] == "mugiwara.scan-report"
    assert raw["schema_version"] == 1
    assert raw["report_id"] == saved.report_id


def test_load_accepts_full_filename_reference(store: ReportStore) -> None:
    saved = _save_one(store)

    assert store.load(f"{saved.report_id}.json").report_id == saved.report_id


# -- unique IDs and collisions ---------------------------------------------


def test_generated_ids_are_unique_within_same_second() -> None:
    first = generate_report_id(MOMENT)
    second = generate_report_id(MOMENT)

    assert first != second
    for report_id in (first, second):
        assert REPORT_ID_PATTERN.match(report_id), report_id


def test_consecutive_saves_never_collide_or_overwrite(store: ReportStore) -> None:
    first = _save_one(store, now=MOMENT)
    second = _save_one(
        store,
        now=MOMENT,
        report=_report(_finding(title="Different finding")),
    )

    assert first.report_id != second.report_id
    reloaded_first = store.load(first.report_id)
    titles = {finding.title for finding in reloaded_first.scan.findings}
    assert titles == {"SQL injection in user lookup"}


def test_collision_with_preexisting_file_gets_suffix_not_overwrite(
    store: ReportStore,
) -> None:
    fixed = generate_report_id(MOMENT)
    sentinel = {"keep": True}
    (store.root / f"{fixed}.json").write_text(json.dumps(sentinel), encoding="utf-8")

    monkeypatched = store.save(
        _report(),
        target=_target(),
        configuration=_configuration(),
        now=MOMENT,
    )
    # Force the generated ID onto the occupied name path by saving through a
    # patched generator: the store must pick "-2" instead of overwriting.
    import mugiwara.reports.store as store_module

    original = store_module.generate_report_id
    store_module.generate_report_id = lambda now=None: fixed  # type: ignore[assignment]
    try:
        forced = store.save(
            _report(),
            target=_target(),
            configuration=_configuration(),
            now=MOMENT,
        )
    finally:
        store_module.generate_report_id = original  # type: ignore[assignment]

    assert json.loads((store.root / f"{fixed}.json").read_text(encoding="utf-8")) == sentinel
    assert forced.report_id.endswith("-2")
    assert (store.root / f"{forced.report_id}.json").exists()
    assert monkeypatched.report_id != fixed


# -- atomic writes ----------------------------------------------------------


def test_failed_move_leaves_no_partial_canonical_report(
    store: ReportStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def exploding_replace(src: Any, dst: Any) -> None:
        msg = "simulated crash"
        raise OSError(msg)

    monkeypatch.setattr("mugiwara.reports.store.os.replace", exploding_replace)

    with pytest.raises(Exception, match="simulated crash"):
        _save_one(store, now=MOMENT)

    json_files = list(store.root.glob("*.json"))
    leftovers = [p.name for p in store.root.iterdir()]
    assert json_files == []
    assert leftovers == []


def test_successful_save_leaves_no_temporary_files(store: ReportStore) -> None:
    _save_one(store, now=MOMENT)
    _save_one(store, now=MOMENT + timedelta(seconds=1))

    names = sorted(p.name for p in store.root.iterdir())
    assert len(names) == 2
    assert all(not name.startswith(".") for name in names)


# -- clean failures on bad files --------------------------------------------


def test_missing_report_fails_cleanly(store: ReportStore) -> None:
    with pytest.raises(ReportNotFoundError):
        store.load("20990101T000000-deadbeef00")


def test_malformed_json_fails_cleanly(store: ReportStore, tmp_path: Path) -> None:
    reference = "20260823T120000-cafebabe01"
    (store.root / f"{reference}.json").write_text("{not json at all", encoding="utf-8")

    with pytest.raises(ReportFormatError):
        store.load(reference)


def test_unsupported_schema_name_is_rejected(store: ReportStore) -> None:
    reference = "20260823T120001-cafebabe02"
    (store.root / f"{reference}.json").write_text(
        json.dumps({"schema": "some-other-tool.export", "schema_version": 1}),
        encoding="utf-8",
    )

    with pytest.raises(UnsupportedSchemaError):
        store.load(reference)


def test_unsupported_schema_version_is_rejected(store: ReportStore) -> None:
    reference = "20260823T120002-cafebabe03"
    (store.root / f"{reference}.json").write_text(
        json.dumps({"schema": SCHEMA_NAME, "schema_version": 999}),
        encoding="utf-8",
    )

    with pytest.raises(UnsupportedSchemaError):
        store.load(reference)


def test_invalid_envelope_contents_fail_validation(store: ReportStore) -> None:
    reference = "20260823T120003-cafebabe04"
    (store.root / f"{reference}.json").write_text(
        json.dumps(
            {
                "schema": SCHEMA_NAME,
                "schema_version": SCHEMA_VERSION,
                # missing report_id/created_at/target/configuration/scan
                "unrelated": True,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ReportInvalidContentsError):
        store.load(reference)


def test_invalid_inner_scan_report_fails_validation(store: ReportStore) -> None:
    reference = "20260823T120004-cafebabe05"
    payload: dict[str, Any] = {
        "schema": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "report_id": reference,
        "created_at": "2026-08-23T12:00:04Z",
        "target": {"path": "x", "origin": "y"},
        "configuration": {
            "scan_profile": "standard",
            "llm_provider": "mock",
            "llm_model": "m",
            "sandbox_mode": "subprocess",
            "verification_enabled": False,
            "include_evidence": False,
        },
        "scan": {
            "target_path": 12345,
            "scan_profile": "not-a-real-profile-value",
            "findings": [],
        },
    }
    (store.root / f"{reference}.json").write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReportInvalidContentsError):
        store.load(reference)


# -- path traversal containment ---------------------------------------------


@pytest.mark.parametrize(
    ("reference"),
    [
        "../outside.json",
        "..\\..\\secret.json",
        "../../etc/passwd",
        "sub/../../../elsewhere.json",
    ],
)
def test_references_escaping_store_root_are_refused(store: ReportStore, reference: str) -> None:
    with pytest.raises(ReportPathEscapeError):
        store.load(reference)


def test_contained_subpath_reference_that_is_absent_fails_as_missing(store: ReportStore) -> None:
    with pytest.raises(ReportNotFoundError):
        store.load("sub/dir/report.json")


def test_absolute_path_outside_root_is_refused(store: ReportStore, tmp_path: Path) -> None:
    outside = tmp_path / "elsewhere.json"
    outside.write_text(json.dumps({"schema": SCHEMA_NAME}), encoding="utf-8")

    with pytest.raises(ReportPathEscapeError):
        store.load(str(outside))


def test_empty_reference_fails_as_missing(store: ReportStore) -> None:
    with pytest.raises(ReportNotFoundError):
        store.load("   ")


# -- directory creation ------------------------------------------------------


def test_store_creates_nested_directory_tree(tmp_path: Path) -> None:
    root = tmp_path / "deeply" / "nested" / ".mugiwara" / "reports"
    assert not root.exists()

    fresh = ReportStore(root=root)
    saved = _save_one(fresh)

    assert root.is_dir()
    assert (root / f"{saved.report_id}.json").is_file()


# -- history listing and deletion --------------------------------------------


def test_multiple_reports_are_listed_newest_first(store: ReportStore) -> None:
    older = _save_one(store, now=MOMENT)
    newer = _save_one(store, now=MOMENT.replace(second=46))

    summaries = store.list_reports()

    assert isinstance(summaries[0], ReportSummary)
    assert [s.report_id for s in summaries] == [newer.report_id, older.report_id]
    newest = summaries[0]
    assert newest.total_findings == 2
    assert newest.verified_count == 1
    assert newest.suspected_count == 1
    assert newest.target_path == "D:/work/demo-app"


def test_foreign_files_do_not_break_listing(store: ReportStore) -> None:
    _save_one(store, now=MOMENT)
    (store.root / "notes.txt").write_text("ignore me", encoding="utf-8")
    (store.root / "20260823T120000-ababababab.json").write_text("{broken", encoding="utf-8")

    summaries = store.list_reports()

    assert len(summaries) == 1


def test_delete_removes_only_requested_report(store: ReportStore) -> None:
    keep = _save_one(store, now=MOMENT)
    drop = _save_one(store, now=MOMENT.replace(second=50))

    store.delete(drop.report_id)

    with pytest.raises(ReportNotFoundError):
        store.load(drop.report_id)
    assert store.load(keep.report_id).report_id == keep.report_id

    with pytest.raises(ReportNotFoundError):
        store.delete(drop.report_id)


# -- credential-free configuration snapshot ----------------------------------


def _settings_with_secret() -> MugiwaraSettings:
    return MugiwaraSettings(
        _env_file=None,
        llm=LLMConfig(api_key=SecretStr("sk-unit-test-secret-value")),
    )


def test_snapshot_from_settings_excludes_secrets() -> None:
    settings = _settings_with_secret()
    snapshot = snapshot_from_settings(settings).model_dump()

    flattened = json.dumps(snapshot)
    assert "api_key" not in flattened
    assert "sk-unit-test-secret-value" not in flattened


def test_stored_documents_never_contain_credential_values(store: ReportStore) -> None:
    settings = _settings_with_secret()

    saved = store.save(
        _report(),
        target=_target(),
        configuration=snapshot_from_settings(settings),
        now=MOMENT,
    )

    raw_text = (store.root / f"{saved.report_id}.json").read_text(encoding="utf-8")
    assert "sk-unit-test-secret-value" not in raw_text
    assert "api_key" not in raw_text


# -- evidence payloads survive storage untouched ------------------------------


def test_verified_evidence_survives_round_trip(store: ReportStore) -> None:
    evidence = Evidence(poc_script="print('probe')", canary_found=True)
    finding = _finding(status=FindingStatus.VERIFIED, evidence=evidence)
    report = ScanReport(
        target_path="D:/work/demo-app",
        scan_profile="standard",
        findings=[finding],
    )

    saved = store.save(report, target=_target(), configuration=_configuration())
    loaded = store.load(saved.report_id)

    restored = loaded.scan.findings[0].evidence
    assert restored is not None
    assert restored.poc_script == "print('probe')"
    assert restored.canary_found is True


# -- report root resolution ---------------------------------------------------


def test_resolve_prefers_configured_dir_over_target_anchor(tmp_path: Path) -> None:
    configured = tmp_path / "configured-reports"
    settings = MugiwaraSettings(
        _env_file=None,
        output=OutputConfig(reports_dir=str(configured)),
    )

    resolved = resolve_report_root(settings, target_path=tmp_path / "target")

    assert resolved == configured.resolve()


def test_resolve_anchors_to_scanned_project_when_unconfigured(tmp_path: Path) -> None:
    settings = MugiwaraSettings(_env_file=None)
    target = tmp_path / "project"

    resolved = resolve_report_root(settings, target_path=target)

    assert resolved == (target / ".mugiwara" / "reports").resolve()


def test_resolve_falls_back_to_cwd_without_config_or_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    settings = MugiwaraSettings(_env_file=None)

    resolved = resolve_report_root(settings, target_path=None)

    assert resolved == (tmp_path / ".mugiwara" / "reports").resolve()


# -- authoritative summary enforcement ----------------------------------------


def test_save_persists_recomputed_summary_not_stale_counters(store: ReportStore) -> None:
    report = _report()
    stale = report.summary.model_copy(update={"total_findings": 999})
    tampered = report.model_copy(update={"summary": stale})

    saved = store.save(tampered, target=_target(), configuration=_configuration())

    reloaded = store.load(saved.report_id)
    raw = json.loads((store.root / f"{saved.report_id}.json").read_text(encoding="utf-8"))
    assert reloaded.scan.summary.total_findings == 2
    assert raw["scan"]["summary"]["total_findings"] == 2


def test_load_normalizes_stale_summary_written_by_foreign_writer(
    store: ReportStore,
) -> None:
    saved = _save_one(store, now=MOMENT)
    path = store.root / f"{saved.report_id}.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["scan"]["summary"] = {
        "total_findings": 999,
        "critical_count": 999,
        "high_count": 999,
        "medium_count": 0,
        "low_count": 0,
        "info_count": 0,
        "verified_count": 999,
        "suspected_count": 999,
        "false_positive_count": 0,
        "fixed_count": 0,
    }
    path.write_text(json.dumps(document), encoding="utf-8")

    loaded = store.load(saved.report_id)

    assert loaded.scan.summary.total_findings == 2
    assert loaded.scan.summary.verified_count == 1
    summaries = store.list_reports()
    matching = [item for item in summaries if item.report_id == loaded.report_id]
    assert matching[0].total_findings == 2
