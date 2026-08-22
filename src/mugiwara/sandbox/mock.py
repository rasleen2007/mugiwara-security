"""Deterministic mock sandbox for zero-infrastructure unit and integration testing."""

import asyncio
from collections.abc import Mapping, Sequence

from mugiwara.core.exceptions import (
    SandboxExecutionError,
    SandboxNotRunningError,
    SandboxStartError,
)
from mugiwara.sandbox.base import BaseSandbox, ExecResult, SandboxState, WorkspaceMount


class MockSandbox(BaseSandbox):
    """Deterministic mock backend that simulates sandbox execution without containers.

    Mirrors the behaviour contract of :class:`~mugiwara.sandbox.docker.DockerSandbox`
    (lifecycle states, timeout errors, not-running guards) while performing no
    I/O at all. Responses can be queued sequentially or synthesized from simple
    defaults, making it the default backend for unit tests.
    """

    def __init__(
        self,
        default_exit_code: int = 0,
        default_stdout: str = "",
        default_stderr: str = "",
        default_duration_seconds: float = 0.001,
    ) -> None:
        """Configure the deterministic result used when no queued result matches."""
        super().__init__()
        self._default_exit_code = default_exit_code
        self.default_stdout = default_stdout
        self.default_stderr = default_stderr
        self.default_duration_seconds = default_duration_seconds
        self.mock_results: list[ExecResult] = []
        self.simulated_error: Exception | None = None
        self.call_history: list[list[str]] = []
        self.start_count: int = 0
        self.stop_count: int = 0
        self.last_workspace_mount: WorkspaceMount | None = None

    @property
    def backend_name(self) -> str:
        """Return provider identifier string."""
        return "mock"

    def add_result(self, result: ExecResult) -> None:
        """Queue a sequential result to be returned by future exec_command() calls."""
        self.mock_results.append(result)

    def set_error(self, error: Exception | None) -> None:
        """Configure an exception to be raised by the next lifecycle operation."""
        self.simulated_error = error

    def reset(self) -> None:
        """Clear call history, queued results, and simulated errors."""
        self.mock_results.clear()
        self.simulated_error = None
        self.call_history.clear()
        self.start_count = 0
        self.stop_count = 0
        self.last_workspace_mount = None
        self._state = SandboxState.NOT_CREATED

    async def start(self, workspace_mount: WorkspaceMount | None = None) -> None:
        """Simulate starting an ephemeral sandbox environment."""
        if self.simulated_error is not None:
            raise self.simulated_error
        if self._state == SandboxState.RUNNING:
            msg = f"Mock sandbox '{self.session_id}' is already running."
            raise SandboxStartError(msg)

        self.last_workspace_mount = workspace_mount
        self.start_count += 1
        self._state = SandboxState.RUNNING

    async def exec_command(
        self,
        command: Sequence[str],
        *,
        timeout_seconds: float | None = None,
        environment: Mapping[str, str] | None = None,
        workdir: str | None = None,
    ) -> ExecResult:
        """Simulate command execution with recorded telemetry."""
        if self.simulated_error is not None:
            raise self.simulated_error
        if self._state != SandboxState.RUNNING:
            msg = f"Mock sandbox '{self.session_id}' is not running; call start() first."
            raise SandboxNotRunningError(msg)
        argv = list(command)
        if not argv:
            msg = "Command argument vector must not be empty."
            raise SandboxExecutionError(msg)

        self.call_history.append(argv)

        if self.mock_results:
            return self.mock_results.pop(0).model_copy(
                update={"command": argv},
            )

        await asyncio.sleep(0)
        return ExecResult(
            command=argv,
            exit_code=self._default_exit_code,
            stdout=self.default_stdout,
            stderr=self.default_stderr,
            duration_seconds=self.default_duration_seconds,
        )

    async def stop(self) -> None:
        """Simulate teardown of the sandbox environment (idempotent)."""
        if self.simulated_error is not None:
            raise self.simulated_error
        self.stop_count += 1
        self.last_workspace_mount = None
        self._state = SandboxState.STOPPED
