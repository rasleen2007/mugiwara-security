"""Unit tests for Mugiwara Security CLI foundation."""

import json
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

_COHERENT_SQLI_SOURCE = '''\
"""Tiny coherent Flask target used to exercise remediation flows."""

import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/users")
def list_users():
    """List users matching an unfiltered name parameter."""
    username = request.args.get("username", "")
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    rows = str(cursor.fetchall())
    connection.close()
    return rows


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
'''


def _verified_harness(canary: str) -> ExecResult:
    """Compose verification-phase output proving canary reflection."""
    trace = '{"method": "GET", "url": "http://127.0.0.1:5000/users", "http_status": 200}'
    return ExecResult(
        command=["sh", "-c", "harness"],
        exit_code=0,
        stdout=(
            f"{TARGET_LOG_MARKER}\n"
            " * Running on http://127.0.0.1:5000\n"
            f"{POC_LOG_MARKER}\n"
            f'{{"echo": "{canary}"}}\n'
            f"MUGIWARA_HTTP_TRACE: {trace}\n"
            'MUGIWARA_VERDICT: {"canary_found": true, "http_status": 200, '
            '"notes": "reflected"}\n'
            "MUGIWARA_EXIT:0 READY:0\n"
        ),
        duration_seconds=0.5,
    )


def _postfix_harness(
    verdict_canary_found: bool,
    *,
    echo_canary: str | None = None,
    exit_code: int = 0,
    ready: int = 0,
    target_log: str = " * Running on http://127.0.0.1:5000\n",
    poc_log_extra: str = "",
) -> ExecResult:
    """Compose a post-patch sea-trial harness result."""
    trace = '{"method": "GET", "url": "http://127.0.0.1:5000/users", "http_status": 200}'
    echoed = f"{echo_canary}\n" if echo_canary else ""
    return ExecResult(
        command=["sh", "-c", "harness"],
        exit_code=exit_code,
        stdout=(
            f"{TARGET_LOG_MARKER}\n"
            f"{target_log}"
            f"{POC_LOG_MARKER}\n"
            f"{poc_log_extra}"
            f"{echoed}"
            f"MUGIWARA_HTTP_TRACE: {trace}\n"
            f'MUGIWARA_VERDICT: {{"canary_found": {str(verdict_canary_found).lower()}, '
            '"http_status": 200, "notes": "sea trial"}\n'
            f"MUGIWARA_EXIT:{exit_code} READY:{ready}\n"
        ),
        duration_seconds=0.4,
    )


def _clean_postfix_harness() -> ExecResult:
    """Post-patch output where the exploit demonstrably stopped reproducing."""
    return _postfix_harness(False)


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
    """Verify that a remote provider aborts the live scan with exit code 1."""
    result = runner.invoke(app, ["scan", "./src", "--provider", "openai"])
    assert result.exit_code == 1
    assert "Scan failed" in result.stdout
    assert "not implemented" in result.stdout


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


def test_cli_report_missing_reference_fails_cleanly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify report show and export fail cleanly for unknown reports."""
    monkeypatch.chdir(tmp_path)
    r_show = runner.invoke(app, ["report", "show", "20990101T000000-deadbeef00"])
    assert r_show.exit_code == 1
    assert "not found" in r_show.stdout.lower()

    r_export = runner.invoke(
        app, ["report", "export", "20990101T000000-deadbeef00", "--format", "sarif"]
    )
    assert r_export.exit_code == 1
    assert "not found" in r_export.stdout.lower()


def test_cli_fix_deferred() -> None:
    """Verify fix command help advertises the Phase 6 remediation workflow."""
    result = runner.invoke(app, ["fix", "--help"])
    assert result.exit_code == 0
    assert "sea trial" in result.stdout.lower()


def test_cli_fix_mock_sandbox_verified_fixed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify the full fix pipeline reaches VERIFIED_FIXED on the mock backend."""
    target = tmp_path / "sqli_app"
    target.mkdir()
    (target / "app.py").write_text(_COHERENT_SQLI_SOURCE, encoding="utf-8")
    original_content = (target / "app.py").read_text(encoding="utf-8")

    provider = MockLLMProvider()
    monkeypatch.setattr("mugiwara.agents.orchestrator.get_provider", lambda _config: provider)
    monkeypatch.setattr("mugiwara.remediation.service.get_provider", lambda _config: provider)
    sandbox = MockSandbox()
    sandbox.add_result(_verified_harness(FIXED_CANARY))
    sandbox.add_result(_clean_postfix_harness())
    monkeypatch.setattr("mugiwara.agents.orchestrator.get_sandbox", lambda _config: sandbox)
    monkeypatch.setattr("mugiwara.remediation.service.get_sandbox", lambda _config: sandbox)
    monkeypatch.setattr("mugiwara.agents.verification.gen_canary_token", lambda: FIXED_CANARY)

    bundle_file = tmp_path / "fix-bundle.json"
    result = runner.invoke(
        app,
        [
            "fix",
            str(target),
            "--provider",
            "mock",
            "--sandbox",
            "mock",
            "--output",
            str(bundle_file),
        ],
    )

    assert result.exit_code == 0
    flattened = " ".join(result.stdout.split())
    assert "VERIFIED_FIXED" in flattened
    assert "Threat Defeated" in flattened
    assert bundle_file.is_file()

    payload = json.loads(bundle_file.read_text(encoding="utf-8"))
    assert payload["schema"] == "mugiwara.fix-bundle"
    assert payload["summary"]["VERIFIED_FIXED"] == 1
    record = payload["remediations"][0]
    assert record["status"] == "VERIFIED_FIXED"
    assert "-cursor.execute" in record["unified_diff"].replace("\n", "") or (
        "-    cursor.execute" in record["unified_diff"]
    )
    assert "(username,)" in record["patched_content"]
    assert record["post_validation_evidence"]["canary_found"] is False

    assert (target / "app.py").read_text(encoding="utf-8") == original_content


def test_cli_fix_nothing_to_do_exits_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify a target without verified findings finishes cleanly with exit 0."""
    target = tmp_path / "clean_app"
    target.mkdir()
    (target / "main.py").write_text("value = 1\nprint(value)\n", encoding="utf-8")

    provider = MockLLMProvider()
    monkeypatch.setattr("mugiwara.agents.orchestrator.get_provider", lambda _config: provider)
    monkeypatch.setattr("mugiwara.remediation.service.get_provider", lambda _config: provider)

    result = runner.invoke(
        app,
        ["fix", str(target), "--provider", "mock", "--sandbox", "none"],
    )

    assert result.exit_code == 0
    flattened = " ".join(result.stdout.split())
    assert "No dynamically verified findings to remediate." in flattened


def test_cli_invalid_command() -> None:
    """Verify that calling an unknown command exits with code 2."""
    result = runner.invoke(app, ["unknown-command-xyz"])
    assert result.exit_code == 2


def _fixture_target() -> Path:
    return Path(__file__).resolve().parents[1] / "fixtures" / "sample_vulnerable_app"


def test_cli_scan_format_sarif_writes_valid_sarif_file(tmp_path: Path) -> None:
    """Verify --format sarif writes genuine SARIF 2.1.0 to the output file."""
    sarif_file = tmp_path / "results.sarif"

    result = runner.invoke(
        app,
        [
            "scan",
            str(_fixture_target()),
            "--provider",
            "mock",
            "--sandbox",
            "none",
            "--format",
            "sarif",
            "--output",
            str(sarif_file),
        ],
    )

    assert result.exit_code == 2
    assert sarif_file.is_file()
    document = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert document["version"] == "2.1.0"
    driver = document["runs"][0]["tool"]["driver"]
    assert driver["name"] == "MugiwaraSecurity"
    results = document["runs"][0]["results"]
    assert len(results) >= 1
    statuses = {r["properties"]["mugiwara:status"] for r in results}
    assert "false_positive" not in statuses


def test_cli_scan_format_sarif_stdout_without_output_file() -> None:
    """Verify --format sarif without --output streams the SARIF JSON to stdout."""
    result = runner.invoke(
        app,
        [
            "scan",
            str(_fixture_target()),
            "--provider",
            "mock",
            "--sandbox",
            "none",
            "--format",
            "sarif",
        ],
    )

    assert result.exit_code == 2
    assert '"version": "2.1.0"' in result.stdout
    assert '"name": "MugiwaraSecurity"' in result.stdout


def test_cli_scan_format_markdown_renders_report(tmp_path: Path) -> None:
    """Verify markdown scan output writes a full Markdown report document."""
    report_file = tmp_path / "report.md"
    result = runner.invoke(
        app,
        [
            "scan",
            str(_fixture_target()),
            "--provider",
            "mock",
            "--sandbox",
            "none",
            "--format",
            "markdown",
            "--output",
            str(report_file),
        ],
    )

    assert result.exit_code == 2
    content = report_file.read_text(encoding="utf-8")
    assert "# Mugiwara Security Report" in content
    assert "## Summary" in content
    assert "## Finding 1:" in content
    assert '"$schema"' not in content


def test_cli_scan_text_and_json_output_files_unchanged(tmp_path: Path) -> None:
    """Verify text/json formats keep writing the internal report schema."""
    report_file = tmp_path / "report.json"

    result = runner.invoke(
        app,
        [
            "scan",
            str(_fixture_target()),
            "--provider",
            "mock",
            "--sandbox",
            "none",
            "--output",
            str(report_file),
        ],
    )

    assert result.exit_code == 2
    payload = report_file.read_text(encoding="utf-8")
    assert '"total_findings"' in payload
    assert '"$schema"' not in payload
    assert '"version": "2.1.0"' not in payload
