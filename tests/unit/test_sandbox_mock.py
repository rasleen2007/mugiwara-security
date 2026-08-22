"""Unit tests for the deterministic MockSandbox backend."""

from pathlib import Path

import pytest

from mugiwara.core.exceptions import (
    SandboxExecutionError,
    SandboxNotRunningError,
    SandboxStartError,
)
from mugiwara.sandbox.base import ExecResult, SandboxState, WorkspaceMount
from mugiwara.sandbox.mock import MockSandbox


async def test_mock_sandbox_lifecycle_states() -> None:
    """Verify lifecycle state transitions and counters."""
    sandbox = MockSandbox()
    initial_state = sandbox.state
    assert initial_state == SandboxState.NOT_CREATED
    assert sandbox.is_running is False
    assert sandbox.backend_name == "mock"
    assert sandbox.session_id

    await sandbox.start()
    running_state = sandbox.state
    assert running_state == SandboxState.RUNNING
    assert sandbox.is_running is True

    await sandbox.stop()
    final_state = sandbox.state
    assert final_state == SandboxState.STOPPED
    assert sandbox.is_running is False
    assert sandbox.start_count == 1
    assert sandbox.stop_count == 1


async def test_mock_sandbox_stop_is_idempotent() -> None:
    """Verify repeated stop() calls are safe."""
    sandbox = MockSandbox()
    await sandbox.start()
    await sandbox.stop()
    await sandbox.stop()
    await sandbox.stop()
    assert sandbox.stop_count == 3


async def test_mock_sandbox_double_start_rejected() -> None:
    """Verify starting an already-running sandbox raises a typed error."""
    sandbox = MockSandbox()
    await sandbox.start()
    with pytest.raises(SandboxStartError, match="already running"):
        await sandbox.start()


async def test_mock_sandbox_default_result_synthesis() -> None:
    """Verify deterministic default results when nothing is queued."""
    sandbox = MockSandbox(
        default_exit_code=3,
        default_stdout="probe output",
        default_stderr="probe noise",
        default_duration_seconds=0.5,
    )
    await sandbox.start()

    result = await sandbox.exec_command(["python", "poc.py"])

    assert isinstance(result, ExecResult)
    assert result.command == ["python", "poc.py"]
    assert result.exit_code == 3
    assert result.stdout == "probe output"
    assert result.stderr == "probe noise"
    assert result.duration_seconds == 0.5
    assert result.timed_out is False
    assert sandbox.call_history == [["python", "poc.py"]]


async def test_mock_sandbox_queued_results_fifo() -> None:
    """Verify queued results are returned in FIFO order with command rebinding."""
    sandbox = MockSandbox(default_exit_code=0, default_stdout="fallback")
    sandbox.add_result(ExecResult(command=[], exit_code=7, stdout="first"))
    sandbox.add_result(ExecResult(command=[], exit_code=8, stdout="second"))
    await sandbox.start()

    r1 = await sandbox.exec_command(["cmd", "one"])
    r2 = await sandbox.exec_command(["cmd", "two"])
    r3 = await sandbox.exec_command(["cmd", "three"])

    assert (r1.exit_code, r1.stdout) == (7, "first")
    assert (r2.exit_code, r2.stdout) == (8, "second")
    assert (r3.exit_code, r3.stdout) == (0, "fallback")
    # Queued commands are rebound to the actual invocation argv.
    assert r1.command == ["cmd", "one"]
    assert r2.command == ["cmd", "two"]
    assert len(sandbox.call_history) == 3


async def test_mock_sandbox_records_workspace_mount(tmp_path: Path) -> None:
    """Verify workspace mounts are validated and recorded on start."""
    project = tmp_path / "workspace-project"
    project.mkdir()
    mount = WorkspaceMount(host_path=project)

    sandbox = MockSandbox()
    await sandbox.start(workspace_mount=mount)
    assert sandbox.last_workspace_mount is mount

    await sandbox.stop()
    assert sandbox.last_workspace_mount is None


async def test_mock_sandbox_exec_requires_running_state() -> None:
    """Verify exec before start raises SandboxNotRunningError."""
    sandbox = MockSandbox()
    with pytest.raises(SandboxNotRunningError):
        await sandbox.exec_command(["ls"])

    await sandbox.start()
    await sandbox.stop()
    with pytest.raises(SandboxNotRunningError):
        await sandbox.exec_command(["ls"])


async def test_mock_sandbox_empty_command_rejected() -> None:
    """Verify empty command vectors raise SandboxExecutionError."""
    sandbox = MockSandbox()
    await sandbox.start()
    with pytest.raises(SandboxExecutionError, match="empty"):
        await sandbox.exec_command([])


async def test_mock_sandbox_simulated_timeout_error() -> None:
    """Verify simulated errors propagate verbatim from every operation."""
    from mugiwara.core.exceptions import SandboxTimeoutError

    sandbox = MockSandbox()
    timeout_error = SandboxTimeoutError("Simulated command hang.")
    sandbox.set_error(timeout_error)

    with pytest.raises(SandboxTimeoutError, match="Simulated command hang."):
        await sandbox.start()

    sandbox.set_error(None)
    await sandbox.start()
    sandbox.set_error(timeout_error)
    with pytest.raises(SandboxTimeoutError, match="Simulated command hang."):
        await sandbox.exec_command(["hang"])
    with pytest.raises(SandboxTimeoutError, match="Simulated command hang."):
        await sandbox.stop()


async def test_mock_sandbox_context_manager_guarantees_cleanup_on_exception() -> None:
    """Verify async-with teardown runs even when the body raises."""
    sandbox = MockSandbox()
    with pytest.raises(RuntimeError, match="boom"):  # noqa: PT012 - multi-statement body
        async with sandbox as entered:
            assert entered is sandbox
            await entered.exec_command(["check"])
            raise RuntimeError("boom")

    assert sandbox.state == SandboxState.STOPPED


async def test_mock_sandbox_reset_clears_all_state() -> None:
    """Verify reset restores pristine mock state."""
    sandbox = MockSandbox(default_stdout="x")
    sandbox.add_result(ExecResult(command=["a"], exit_code=1))
    await sandbox.start()
    await sandbox.exec_command(["probe"])
    sandbox.set_error(RuntimeError("err"))

    sandbox.reset()

    assert len(sandbox.mock_results) == 0
    assert sandbox.simulated_error is None
    assert len(sandbox.call_history) == 0
    assert sandbox.start_count == 0
    assert sandbox.stop_count == 0
    assert sandbox.state == SandboxState.NOT_CREATED
