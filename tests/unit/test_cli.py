"""Unit tests for Mugiwara Security CLI foundation."""

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from mugiwara import __version__
from mugiwara.cli.main import app
from mugiwara.sandbox import DockerSandbox

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


def test_cli_scan_live_not_implemented() -> None:
    """Verify that 'mugiwara scan' without --dry-run exits with code 1 and deferred notice."""
    result = runner.invoke(app, ["scan", "./src"])
    assert result.exit_code == 1
    assert "Active scanning is not implemented yet" in result.stdout
    assert "Use '--dry-run'" in result.stdout


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
