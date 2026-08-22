"""Unit tests for Mugiwara Security CLI foundation."""

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from mugiwara import __version__
from mugiwara.agents.models import (
    AttackSurfaceMap,
    Endpoint,
    SuspectedFindingsReport,
    VerificationPlan,
)
from mugiwara.agents.poc_safety import POC_LOG_MARKER, TARGET_LOG_MARKER
from mugiwara.cli.main import app
from mugiwara.providers.mock import MockLLMProvider
from mugiwara.sandbox import DockerSandbox
from mugiwara.sandbox.base import ExecResult
from mugiwara.sandbox.mock import MockSandbox
from tests.unit.test_agents_orchestrator import FIXED_CANARY, SAFE_POC_SCRIPT

runner = CliRunner()


def _fake_availability(available: bool) -> Any:
    """Build a patched DockerSandbox.is_docker_available classmethod."""

    def probe(cls: type) -> bool:
        return available

    return classmethod(probe)


def test_cli_version_flag() -> None:
    """Verify that --version and -v print version and exit with code 0."""
    result_long = runner.invoke(app, ["--version"])
    assert result_long.exit_code == 0
    assert f"Mugiwara Security v{__version__}" in result_long.stdout

    result_short = runner.invoke(app, ["-v"])
    assert result_short.exit_code == 0
    assert f"Mugiwara Security v{__version__}" in result_short.stdout


def test_cli_help() -> None:
    """Verify that --help lists subcommands and exits with code 0."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "init" in result.stdout
    assert "scan" in result.stdout
    assert "config" in result.stdout
    assert "sandbox" in result.stdout
    assert "report" in result.stdout
    assert "fix" in result.stdout


def test_cli_init_creates_file(tmp_path: Path) -> None:
    """Verify that 'mugiwara init' creates mugiwara.yaml."""
    target = tmp_path / "mugiwara.yaml"
    result = runner.invoke(app, ["init", "--path", str(target)])

    assert result.exit_code == 0
    assert "Initialized configuration file" in result.stdout
    assert target.is_file()
    content = target.read_text(encoding="utf-8")
    assert "llm:" in content
    assert "sandbox:" in content


def test_cli_init_existing_file_without_force(tmp_path: Path) -> None:
    """Verify that 'mugiwara init' on existing file without --force warns and exits 0."""
    target = tmp_path / "mugiwara.yaml"
    target.write_text("existing: true\n", encoding="utf-8")

    result = runner.invoke(app, ["init", "--path", str(target)])
    assert result.exit_code == 0
    assert "already exists" in result.stdout
    assert target.read_text(encoding="utf-8") == "existing: true\n"


def test_cli_init_existing_file_with_force(tmp_path: Path) -> None:
    """Verify that 'mugiwara init --force' overwrites existing file."""
    target = tmp_path / "mugiwara.yaml"
    target.write_text("existing: true\n", encoding="utf-8")

    result = runner.invoke(app, ["init", "--path", str(target), "--force"])
    assert result.exit_code == 0
    assert "Initialized configuration file" in result.stdout
    assert "existing: true" not in target.read_text(encoding="utf-8")


def test_cli_config_show(tmp_path: Path) -> None:
    """Verify that 'mugiwara config show' displays formatted configuration table."""
    config_file = tmp_path / "mugiwara.yaml"
    config_file.write_text("log_level: DEBUG\n", encoding="utf-8")

    result = runner.invoke(app, ["config", "show", "--config-file", str(config_file)])
    assert result.exit_code == 0
    assert "Mugiwara Security Configuration" in result.stdout
    assert "log_level" in result.stdout
    assert "DEBUG" in result.stdout


def test_cli_config_show_missing_file() -> None:
    """Verify that 'mugiwara config show' with missing file exits with code 1."""
    result = runner.invoke(app, ["config", "show", "--config-file", "nonexistent.yaml"])
    assert result.exit_code == 1
    assert "Configuration file not found" in result.stdout


def test_cli_config_set(tmp_path: Path) -> None:
    """Verify updating configuration keys with 'mugiwara config set'."""
    config_file = tmp_path / "mugiwara.yaml"
    config_file.write_text("log_level: INFO\n", encoding="utf-8")

    # Set string value
    res1 = runner.invoke(
        app, ["config", "set", "llm.model", "gpt-4o-mini", "--config-file", str(config_file)]
    )
    assert res1.exit_code == 0
    assert "Updated 'llm.model' to 'gpt-4o-mini'" in res1.stdout

    # Set boolean value
    res2 = runner.invoke(
        app, ["config", "set", "scan.dry_run", "true", "--config-file", str(config_file)]
    )
    assert res2.exit_code == 0

    # Set integer value
    res3 = runner.invoke(
        app, ["config", "set", "scan.max_turns", "25", "--config-file", str(config_file)]
    )
    assert res3.exit_code == 0

    # Verify updated content
    content = config_file.read_text(encoding="utf-8")
    assert "gpt-4o-mini" in content
    assert "dry_run: true" in content
    assert "max_turns: 25" in content


def test_cli_config_set_invalid_value(tmp_path: Path) -> None:
    """Verify that setting invalid values triggers Pydantic validation and exits code 1."""
    config_file = tmp_path / "mugiwara.yaml"
    config_file.write_text("log_level: INFO\n", encoding="utf-8")

    result = runner.invoke(
        app, ["config", "set", "llm.temperature", "5.0", "--config-file", str(config_file)]
    )
    assert result.exit_code == 1
    assert "Invalid configuration value" in result.stdout


def test_cli_scan_dry_run() -> None:
    """Verify that 'mugiwara scan --dry-run' prints scan plan and exits code 0."""
    result = runner.invoke(
        app,
        [
            "scan",
            "./src",
            "--profile",
            "fast",
            "--provider",
            "mock",
            "--model",
            "mock-v1",
            "--sandbox",
            "none",
            "--format",
            "json",
            "--dry-run",
        ],
    )
    assert result.exit_code == 0
    assert "Mugiwara Scan Plan (Dry Run)" in result.stdout
    assert "fast" in result.stdout
    assert "mock" in result.stdout
    assert "mock-v1" in result.stdout
    assert "Dry run completed successfully" in result.stdout


def test_cli_scan_live_deferred_provider_fails() -> None:
    """Verify that a non-mock provider aborts the live scan with exit code 1."""
    result = runner.invoke(app, ["scan", "./src"])
    assert result.exit_code == 1
    assert "Scan failed" in result.stdout
    assert "deferred" in result.stdout


def test_cli_scan_live_mock_provider_exits_two(tmp_path: Path) -> None:
    """Verify a live mock-provider scan reports findings and exits with code 2."""
    fixture = Path(__file__).resolve().parents[1] / "fixtures" / "sample_vulnerable_app"
    report_file = tmp_path / "scan-report.json"

    result = runner.invoke(
        app,
        [
            "scan",
            str(fixture),
            "--provider",
            "mock",
            "--sandbox",
            "none",
            "--output",
            str(report_file),
        ],
    )

    assert result.exit_code == 2
    assert "Mugiwara Scan Summary" in result.stdout
    assert "Report written to" in result.stdout
    assert report_file.is_file()

    payload = report_file.read_text(encoding="utf-8")
    assert '"high_count"' in payload
    assert '"total_findings": 0' not in payload


def test_cli_scan_live_mock_provider_clean_target_exits_zero(tmp_path: Path) -> None:
    """Verify a clean target scans without findings and exits with code 0."""
    clean = tmp_path / "clean_app"
    clean.mkdir()
    (clean / "main.py").write_text("value = 1 + 2\nprint(value)\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["scan", str(clean), "--provider", "mock", "--sandbox", "none"],
    )

    assert result.exit_code == 0
    flattened = " ".join(result.stdout.split())
    assert "No actionable critical or high severity findings" in flattened


def test_cli_scan_skip_verification_flag_honored() -> None:
    """Verify --skip-verification keeps the sandbox backend untouched."""
    fixture = Path(__file__).resolve().parents[1] / "fixtures" / "sample_vulnerable_app"

    result = runner.invoke(
        app,
        [
            "scan",
            str(fixture),
            "--provider",
            "mock",
            "--sandbox",
            "mock",
            "--skip-verification",
        ],
    )

    assert result.exit_code == 2
    assert "Sandbox Backend" not in result.stdout


def test_cli_scan_verification_rows_rendered_with_mock_sandbox(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify verification diagnostics render when the phase runs on mock sandbox."""
    fixture = Path(__file__).resolve().parents[1] / "fixtures" / "sample_vulnerable_app"
    monkeypatch.setattr(
        "mugiwara.agents.orchestrator.get_sandbox",
        lambda _config: MockSandbox(),
    )

    result = runner.invoke(
        app,
        ["scan", str(fixture), "--provider", "mock", "--sandbox", "mock"],
    )

    assert result.exit_code == 2
    assert "Sandbox Backend" in result.stdout
    assert "Verification Candidates" in result.stdout


def test_cli_scan_false_positive_excluded_from_exit_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify a FALSE_POSITIVE elimination downgrades exit code 2 to 0."""
    target = tmp_path / "sqli_app"
    target.mkdir()
    (target / "app.py").write_text(
        "from flask import Flask, request\n"
        "import sqlite3\n"
        "\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/users')\n"
        "def users():\n"
        "    uid = request.args.get('id')\n"
        "    conn = sqlite3.connect(':memory:')\n"
        "    cur = conn.cursor()\n"
        "    cur.execute(f'SELECT * FROM users WHERE id = {uid}')\n"
        "    return str(cur.fetchall())\n",
        encoding="utf-8",
    )

    provider = MockLLMProvider()
    provider.add_structured_response(
        AttackSurfaceMap(
            summary="Tiny SQLi service.",
            endpoints=[Endpoint(path="/users", method="GET", source_file="app.py")],
        )
    )
    provider.add_structured_response(SuspectedFindingsReport(findings=[]))
    provider.add_structured_response(VerificationPlan(finding_ref=0, poc_script=SAFE_POC_SCRIPT))
    monkeypatch.setattr(
        "mugiwara.agents.orchestrator.get_provider",
        lambda _config: provider,
    )
    sandbox = MockSandbox()
    trace = '{"method": "GET", "url": "http://127.0.0.1:5000/users", "http_status": 200}'
    sandbox.add_result(
        ExecResult(
            command=["sh", "-c", "harness"],
            exit_code=0,
            stdout=(
                f"{TARGET_LOG_MARKER}\n"
                "running\n"
                f"{POC_LOG_MARKER}\n"
                f"MUGIWARA_HTTP_TRACE: {trace}\n"
                'MUGIWARA_VERDICT: {"canary_found": false, "http_status": 200, "notes": "clean"}\n'
                "MUGIWARA_EXIT:0 READY:0\n"
            ),
            duration_seconds=0.4,
        )
    )
    monkeypatch.setattr(
        "mugiwara.agents.orchestrator.get_sandbox",
        lambda _config: sandbox,
    )
    monkeypatch.setattr(
        "mugiwara.agents.verification.gen_canary_token",
        lambda: FIXED_CANARY,
    )

    result = runner.invoke(
        app,
        ["scan", str(target), "--provider", "mock", "--sandbox", "mock"],
    )

    assert result.exit_code == 0
    assert "False Positives" in result.stdout
    flattened = " ".join(result.stdout.split())
    assert "No actionable critical or high severity findings" in flattened


def test_cli_sandbox_status_available(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify 'mugiwara sandbox status' reports an operational backend."""
    from mugiwara.cli.commands import sandbox as sandbox_module
    from mugiwara.sandbox.base import SandboxStatus

    fake_status = SandboxStatus(
        backend="docker",
        available=True,
        message="Docker daemon is reachable.",
        managed_containers=2,
        managed_networks=1,
    )
    monkeypatch.setattr(sandbox_module, "get_sandbox_status", lambda: fake_status)

    result = runner.invoke(app, ["sandbox", "status"])
    assert result.exit_code == 0
    assert "Mugiwara Sandbox Status" in result.stdout
    assert "docker" in result.stdout
    assert "Sandbox backend is operational" in result.stdout


def test_cli_sandbox_status_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify 'mugiwara sandbox status' exits 1 when Docker is unreachable."""
    from mugiwara.cli.commands import sandbox as sandbox_module
    from mugiwara.sandbox.base import SandboxStatus

    fake_status = SandboxStatus(
        backend="docker",
        available=False,
        message="Docker daemon is not reachable: connection refused",
    )
    monkeypatch.setattr(sandbox_module, "get_sandbox_status", lambda: fake_status)

    result = runner.invoke(app, ["sandbox", "status"])
    assert result.exit_code == 1
    assert "not available" in result.stdout


def test_cli_sandbox_cleanup_no_leftovers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify cleanup succeeds immediately when no resources remain."""
    from mugiwara.cli.commands import sandbox as sandbox_module
    from mugiwara.sandbox.base import SandboxStatus

    monkeypatch.setattr(DockerSandbox, "is_docker_available", _fake_availability(True))
    monkeypatch.setattr(
        sandbox_module,
        "get_sandbox_status",
        lambda: SandboxStatus(backend="docker", available=True, managed_containers=0),
    )

    result = runner.invoke(app, ["sandbox", "cleanup", "--yes"])
    assert result.exit_code == 0
    assert "No leftover Mugiwara sandbox resources" in result.stdout


def test_cli_sandbox_cleanup_removes_resources(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify cleanup removes leftover resources and reports the outcome."""
    from mugiwara.cli.commands import sandbox as sandbox_module
    from mugiwara.sandbox.base import CleanupReport, SandboxStatus

    monkeypatch.setattr(DockerSandbox, "is_docker_available", _fake_availability(True))
    monkeypatch.setattr(
        sandbox_module,
        "get_sandbox_status",
        lambda: SandboxStatus(
            backend="docker", available=True, managed_containers=3, managed_networks=1
        ),
    )
    captured: dict[str, bool] = {}

    def fake_cleanup() -> CleanupReport:
        captured["called"] = True
        return CleanupReport(containers_removed=3, networks_removed=1)

    monkeypatch.setattr(sandbox_module, "cleanup_sandbox_resources", fake_cleanup)

    result = runner.invoke(app, ["sandbox", "cleanup", "--yes"])
    assert result.exit_code == 0
    assert captured.get("called") is True
    assert "Removed 3 container(s)" in result.stdout
    assert "Sandbox cleanup completed successfully" in result.stdout


def test_cli_sandbox_cleanup_aborted_by_user(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify declining the confirmation prompt leaves resources untouched."""
    from mugiwara.cli.commands import sandbox as sandbox_module
    from mugiwara.sandbox.base import SandboxStatus

    monkeypatch.setattr(DockerSandbox, "is_docker_available", _fake_availability(True))
    monkeypatch.setattr(
        sandbox_module,
        "get_sandbox_status",
        lambda: SandboxStatus(backend="docker", available=True, managed_containers=1),
    )
    called: list[bool] = []
    monkeypatch.setattr(sandbox_module, "cleanup_sandbox_resources", lambda: called.append(True))

    result = runner.invoke(app, ["sandbox", "cleanup"], input="n\n")
    assert result.exit_code == 0
    assert "aborted by user" in result.stdout
    assert called == []


def test_cli_sandbox_cleanup_backend_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify cleanup exits 1 when the Docker backend is unavailable."""

    monkeypatch.setattr(DockerSandbox, "is_docker_available", _fake_availability(False))

    result = runner.invoke(app, ["sandbox", "cleanup", "--yes"])
    assert result.exit_code == 1
    assert "not available" in result.stdout


def test_cli_report_deferred() -> None:
    """Verify report show and export exit code 1 with deferred message."""
    r_show = runner.invoke(app, ["report", "show", "report-123"])
    assert r_show.exit_code == 1
    assert "not implemented yet" in r_show.stdout

    r_export = runner.invoke(app, ["report", "export", "report-123", "--format", "sarif"])
    assert r_export.exit_code == 1
    assert "not implemented yet" in r_export.stdout


def test_cli_fix_deferred() -> None:
    """Verify fix command exits code 1 with deferred message and does not modify files."""
    result = runner.invoke(app, ["fix", "finding-456"])
    assert result.exit_code == 1
    assert "not implemented yet" in result.stdout
    assert "No files or patches were modified" in result.stdout


def test_cli_invalid_command() -> None:
    """Verify that calling an unknown command exits with code 2."""
    result = runner.invoke(app, ["unknown-command-xyz"])
    assert result.exit_code == 2
