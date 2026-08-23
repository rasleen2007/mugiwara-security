"""S6 tests: scan progress UX, stream discipline, and exit-code contract."""

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mugiwara.agents.orchestrator import ScanOrchestrator, SessionPhase
from mugiwara.cli.main import app

runner = CliRunner()

FIXTURE_APP = Path(__file__).resolve().parents[1] / "fixtures" / "sample_vulnerable_app"

BENIGN_SOURCE = "value = 1\nprint(value)\n"

_PHASE_LINE = re.compile(r"^phase [a-z ]+: .+$")


def _scan_args(target, *extra: str) -> list[str]:
    return ["scan", str(target), "--provider", "mock", "--no-save-report", *extra]


# ---------------------------------------------------------------------------
# Progress output.
# ---------------------------------------------------------------------------


def test_scan_progress_lines_render_on_stderr_with_counts() -> None:
    """Phase progress carries names and counts on stderr; stdout stays decorative."""
    result = runner.invoke(app, _scan_args(FIXTURE_APP, "--sandbox", "none"))

    assert result.exit_code == 2
    stderr_lines = [line.strip() for line in result.stderr.splitlines()]
    phase_lines = [line for line in stderr_lines if _PHASE_LINE.match(line)]
    assert any(line.startswith("phase scan start:") for line in phase_lines)
    assert any("phase target: files_collected=" in line for line in phase_lines)
    assert any(
        re.search(r"phase recon: components=\d+ endpoints=\d+", line) for line in phase_lines
    )
    assert any("phase discovery: suspected_findings=" in line for line in phase_lines)
    assert any("phase scan complete:" in line for line in phase_lines)

    # No source contents, PoCs, or evidence may leak through progress output.
    assert "api_key" not in result.stderr
    assert "MUGIWARA_VERDICT" not in result.stderr


def test_scan_progress_is_deterministic_across_runs() -> None:
    """Two identical invocations produce byte-identical progress streams."""
    first = runner.invoke(app, _scan_args(FIXTURE_APP, "--sandbox", "none"))
    second = runner.invoke(app, _scan_args(FIXTURE_APP, "--sandbox", "none"))

    assert first.exit_code == second.exit_code == 2
    assert first.stderr == second.stderr


def test_progress_never_contaminates_stdout() -> None:
    """Decorative tables remain on stdout; phase lines never appear there."""
    result = runner.invoke(app, _scan_args(FIXTURE_APP, "--sandbox", "none"))

    assert "Mugiwara Scan Summary" in result.stdout
    assert "Session Diagnostics" in result.stdout
    assert "phase " not in result.stdout


def test_no_color_env_renders_plain_text_identically() -> None:
    """NO_COLOR must not crash or alter the captured text content."""
    plain = runner.invoke(app, _scan_args(FIXTURE_APP, "--sandbox", "none"))
    colored_env_off = runner.invoke(
        app,
        _scan_args(FIXTURE_APP, "--sandbox", "none"),
        env={"NO_COLOR": "1"},
    )

    for result in (plain, colored_env_off):
        assert result.exit_code == 2
        assert "\x1b[" not in result.stdout
        assert "\x1b[" not in result.stderr
    assert colored_env_off.stdout == plain.stdout
    assert colored_env_off.stderr == plain.stderr


def test_captured_non_interactive_output_is_stable() -> None:
    """Captured (non-TTY) invocation renders full tables and phases."""
    result = runner.invoke(app, _scan_args(FIXTURE_APP, "--sandbox", "none"))

    assert result.exit_code == 2
    assert "Total Findings" in result.stdout
    assert "Files Collected" in result.stdout
    assert result.stderr != ""


# ---------------------------------------------------------------------------
# Stream discipline for machine-readable output.
# ---------------------------------------------------------------------------


def test_sarif_stdout_is_pure_parseable_json() -> None:
    """--format sarif without --output streams only the SARIF document."""
    result = runner.invoke(app, _scan_args(FIXTURE_APP, "--sandbox", "none", "--format", "sarif"))

    assert result.exit_code == 2
    document = json.loads(result.stdout)
    assert document["version"] == "2.1.0"
    assert document["runs"][0]["tool"]["driver"]["name"] == "MugiwaraSecurity"
    assert len(document["runs"][0]["results"]) >= 1

    # Decorative output was rerouted to stderr.
    assert "Mugiwara Scan Summary" not in result.stdout
    assert "Mugiwara Scan Summary" in result.stderr
    assert "phase scan start:" in result.stderr


def test_markdown_stdout_is_pure_document() -> None:
    """--format markdown without --output streams only the Markdown report."""
    result = runner.invoke(
        app, _scan_args(FIXTURE_APP, "--sandbox", "none", "--format", "markdown")
    )

    assert result.exit_code == 2
    assert result.stdout.lstrip().startswith("# Mugiwara Security Report")
    assert "Mugiwara Scan Summary" not in result.stdout
    assert "Mugiwara Scan Summary" in result.stderr
    assert "Success:" not in result.stdout


def test_default_format_keeps_tables_on_stdout() -> None:
    """Without a streamed document the historical table behavior is preserved."""
    result = runner.invoke(app, _scan_args(FIXTURE_APP, "--sandbox", "none"))

    assert result.exit_code == 2
    assert "Mugiwara Scan Summary" in result.stdout
    assert "Report written to" not in result.stdout


def test_error_and_warning_output_goes_to_stderr() -> None:
    """Runtime failures print via err_console and keep stdout empty."""
    result = runner.invoke(app, _scan_args("./definitely-missing-target-xyz"))

    assert result.exit_code == 1
    assert "Scan failed" in result.stderr
    assert result.stdout == ""


# ---------------------------------------------------------------------------
# Exit-code contract documentation and behavior.
# ---------------------------------------------------------------------------


def test_scan_help_documents_exit_codes() -> None:
    """`mugiwara scan --help` spells out the 0/1/2 exit-code contract."""
    result = runner.invoke(app, ["scan", "--help"])

    assert result.exit_code == 0
    flattened = " ".join(result.stdout.split())
    assert "Exit codes:" in flattened
    assert "0 = successful scan, no actionable failure" in flattened
    assert "1 = scan, usage, or runtime error" in flattened
    assert "2 = findings requiring attention" in flattened


@pytest.mark.parametrize(
    ("prepare", "extra", "expected_code"),
    [
        ("clean", (), 0),
        ("vulnerable", (), 2),
        ("missing", (), 1),
    ],
)
def test_exit_code_contract_unchanged(
    tmp_path: Path,
    prepare: str,
    extra: tuple[str, ...],
    expected_code: int,
) -> None:
    """The documented 0/1/2 semantics match actual behavior exactly."""
    if prepare == "clean":
        target = tmp_path / "benign"
        target.mkdir()
        (target / "app.py").write_text(BENIGN_SOURCE, encoding="utf-8")
    elif prepare == "vulnerable":
        target = FIXTURE_APP
    else:
        target = tmp_path / "does-not-exist"

    result = runner.invoke(app, _scan_args(target, "--sandbox", "none", *extra))

    assert result.exit_code == expected_code


# ---------------------------------------------------------------------------
# Orchestrator phase-event emission (unit level).
# ---------------------------------------------------------------------------


async def test_orchestrator_emits_ordered_secret_free_phase_events(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The observer receives deterministic events with counts only."""
    from mugiwara.providers.mock import MockLLMProvider
    from mugiwara.sandbox.mock import MockSandbox

    root = tmp_path / "proj"
    root.mkdir()
    (root / "app.py").write_text(BENIGN_SOURCE, encoding="utf-8")

    monkeypatch.setattr(
        "mugiwara.agents.orchestrator.get_provider",
        lambda _config: MockLLMProvider(),
    )
    monkeypatch.setattr(
        "mugiwara.agents.orchestrator.get_sandbox",
        lambda _config, **_: MockSandbox(),
    )

    events: list[tuple[SessionPhase, str]] = []
    settings_seed = {"on_phase": lambda phase, detail: events.append((phase, detail))}

    from mugiwara.core.config import MugiwaraSettings, SandboxMode

    settings = MugiwaraSettings()
    settings.sandbox.mode = SandboxMode.MOCK

    result = await ScanOrchestrator(settings, **settings_seed).run(str(root))

    assert [phase for phase, _detail in events] == [
        SessionPhase.VALIDATING,
        SessionPhase.RECON,
        SessionPhase.DISCOVERY,
        SessionPhase.VERIFICATION,
    ]
    assert re.fullmatch(r"files_collected=\d+ secret_markers=\d+", events[0][1])
    assert re.fullmatch(r"components=\d+ endpoints=\d+", events[1][1])
    assert re.fullmatch(r"suspected_findings=\d+", events[2][1])
    assert re.fullmatch(
        r"attempted=\d+ verified=\d+ false_positives=\d+ unverified=\d+",
        events[3][1],
    )
    assert result.report.target_path == str(root.resolve())
