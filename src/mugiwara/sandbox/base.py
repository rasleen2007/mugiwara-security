"""Base sandbox abstraction, execution DTOs, and workspace mount safety boundaries."""

import asyncio
import fnmatch
import logging
import os
import stat
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from enum import Enum
from pathlib import Path, PurePosixPath
from uuid import uuid4

from pydantic import BaseModel, Field

from mugiwara.core.exceptions import SandboxError, SandboxWorkspaceError

logger = logging.getLogger(__name__)

WORKSPACE_CONTAINER_ROOT = "/workspace"

_FORBIDDEN_SYSTEM_DIR_NAMES = frozenset(
    {
        "bin",
        "boot",
        "dev",
        "etc",
        "lib",
        "lib64",
        "opt",
        "proc",
        "program files",
        "program files (x86)",
        "programdata",
        "$recycle.bin",
        "run",
        "sbin",
        "srv",
        "sys",
        "system volume information",
        "usr",
        "var",
        "windows",
    }
)

_SENSITIVE_COMPONENT_NAMES = frozenset(
    {
        ".aws",
        ".azure",
        ".docker",
        ".gcloud",
        ".gnupg",
        ".kube",
        ".password-store",
        ".ssh",
    }
)

_SENSITIVE_CHILD_PATTERNS = (
    ".env",
    ".env.*",
    "*.pem",
    "*.p12",
    "*.pfx",
    "*.key",
    "*.keystore",
    "*.sock",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
    "id_rsa*",
    ".git-credentials",
    ".htpasswd",
    ".netrc",
    ".npmrc",
    "credentials.json",
)


def _is_sensitive_child_name(name: str) -> bool:
    """Return True if a directory entry name matches a known sensitive pattern."""
    lowered = name.lower()
    return any(fnmatch.fnmatch(lowered, pattern) for pattern in _SENSITIVE_CHILD_PATTERNS)


def _validate_path_safety(resolved: Path, home: Path | None) -> None:
    """Validate structural safety boundaries of an already-resolved host path.

    This pure check (no filesystem interaction beyond path parsing) rejects:

    - Filesystem/drive roots.
    - The current user's home directory itself.
    - Mount targets whose top-level location is a protected system directory.
    - Paths living inside sensitive locations (``.ssh``, ``.aws``, ``.gnupg``...).

    Args:
        resolved: Fully resolved absolute candidate path.
        home: Resolved user home directory, if determinable.

    Raises:
        SandboxWorkspaceError: If any boundary is violated.
    """
    if resolved.parent == resolved:
        msg = f"Refusing to mount filesystem root '{resolved}' as sandbox workspace."
        raise SandboxWorkspaceError(msg)

    if home is not None and resolved == home:
        msg = (
            f"Refusing to mount the user home directory '{resolved}' as sandbox workspace; "
            "it typically exposes SSH keys, credentials, and .env files."
        )
        raise SandboxWorkspaceError(msg)

    components = resolved.parts[1:]
    top_level_name = components[0].lower() if components else ""
    if top_level_name in _FORBIDDEN_SYSTEM_DIR_NAMES:
        msg = (
            f"Refusing to mount system path '{resolved}': "
            f"'{components[0]}' is a protected system location."
        )
        raise SandboxWorkspaceError(msg)

    for component in resolved.parts:
        if component.lower() in _SENSITIVE_COMPONENT_NAMES:
            msg = (
                f"Refusing to mount '{resolved}': path lives inside the sensitive "
                f"location '{component}'."
            )
            raise SandboxWorkspaceError(msg)


def validate_workspace_host_path(host_path: Path | str) -> Path:
    """Validate that a host path is safe to bind-mount into a sandbox container.

    The validation enforces Mugiwara workspace safety boundaries:

    - The target must exist and be a readable directory.
    - Filesystem/drive roots and well-known system directories are rejected.
    - The current user's home directory itself is rejected.
    - Paths inside sensitive locations (``.ssh``, ``.aws``, ``.gnupg``, ...) are rejected.
    - Directories directly containing credentials, SSH keys, ``.env`` files,
      private key material, or Unix socket files (e.g. the Docker socket) are
      rejected; users must mount a dedicated subdirectory instead.

    Args:
        host_path: Host directory intended to be mounted into the sandbox.

    Returns:
        The fully resolved absolute host path on success.

    Raises:
        SandboxWorkspaceError: If any safety boundary is violated.
    """
    raw_path = Path(host_path)
    try:
        resolved = raw_path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        msg = f"Workspace path '{raw_path}' could not be resolved: {exc}"
        raise SandboxWorkspaceError(msg) from exc

    if not resolved.is_dir():
        msg = f"Workspace path '{resolved}' must be an existing directory."
        raise SandboxWorkspaceError(msg)

    try:
        home = Path.home().resolve()
    except (OSError, RuntimeError):  # pragma: no cover - home always resolvable in practice
        home = None

    _validate_path_safety(resolved, home)

    try:
        with os.scandir(resolved) as entries:
            for entry in entries:
                name = entry.name
                if name.lower() in _SENSITIVE_COMPONENT_NAMES:
                    msg = (
                        f"Refusing to mount '{resolved}': it contains sensitive "
                        f"entry '{name}'. Mount a dedicated project subdirectory instead."
                    )
                    raise SandboxWorkspaceError(msg)
                if _is_sensitive_child_name(name):
                    msg = (
                        f"Refusing to mount '{resolved}': it contains potentially "
                        f"sensitive entry '{name}' (credentials, keys, .env files, "
                        f"or sockets are never mounted into sandboxes)."
                    )
                    raise SandboxWorkspaceError(msg)
                try:
                    mode = entry.stat(follow_symlinks=False).st_mode
                except OSError as exc:
                    msg = f"Workspace entry '{name}' in '{resolved}' is not statable: {exc}"
                    raise SandboxWorkspaceError(msg) from exc
                if stat.S_ISSOCK(mode):
                    msg = (
                        f"Refusing to mount '{resolved}': it contains the Unix "
                        f"socket '{name}' (e.g. the Docker socket)."
                    )
                    raise SandboxWorkspaceError(msg)
    except OSError as exc:
        msg = f"Workspace directory '{resolved}' is not readable: {exc}"
        raise SandboxWorkspaceError(msg) from exc

    return resolved


def validate_workspace_container_path(container_path: str) -> str:
    """Validate the container-side mount point for a workspace volume.

    Container-side targets are restricted to the dedicated ``/workspace``
    subtree so callers can never shadow system paths or inject mounts over
    critical container locations such as ``/etc`` or the Docker socket.

    Args:
        container_path: Absolute POSIX path inside the container.

    Returns:
        The normalized container path on success.

    Raises:
        SandboxWorkspaceError: If the target escapes the /workspace subtree.
    """
    candidate = container_path.strip()
    candidate_path = PurePosixPath(candidate)
    workspace_root = PurePosixPath(WORKSPACE_CONTAINER_ROOT)
    inside_subtree = candidate_path == workspace_root or workspace_root in candidate_path.parents
    if not candidate_path.is_absolute() or not inside_subtree:
        msg = (
            f"Container workspace path must live under '{WORKSPACE_CONTAINER_ROOT}', "
            f"got '{container_path}'."
        )
        raise SandboxWorkspaceError(msg)
    segments = [segment for segment in candidate.split("/") if segment]
    if ".." in segments or "." in segments:
        msg = f"Container workspace path '{container_path}' must not contain '.' or '..' segments."
        raise SandboxWorkspaceError(msg)
    normalized = "/" + "/".join(segments)
    if normalized != candidate:
        msg = f"Container workspace path '{container_path}' is not a normalized absolute path."
        raise SandboxWorkspaceError(msg)
    return normalized


class SandboxState(str, Enum):
    """Lifecycle states of a sandbox environment."""

    NOT_CREATED = "not_created"
    RUNNING = "running"
    STOPPED = "stopped"


class SandboxStatus(BaseModel):
    """Diagnostic snapshot of a sandbox backend for CLI reporting."""

    backend: str = Field(description="Sandbox backend identifier (e.g. 'docker').")
    available: bool = Field(description="Whether the backend is reachable and operational.")
    message: str = Field(default="", description="Human-readable diagnostic detail.")
    managed_containers: int = Field(
        default=0,
        ge=0,
        description="Number of live sandbox containers managed by Mugiwara.",
    )
    managed_networks: int = Field(
        default=0,
        ge=0,
        description="Number of live sandbox networks managed by Mugiwara.",
    )


class CleanupReport(BaseModel):
    """Outcome summary of a best-effort sweep of leftover sandbox resources."""

    containers_removed: int = Field(
        default=0,
        ge=0,
        description="Number of leftover sandbox containers removed.",
    )
    networks_removed: int = Field(
        default=0,
        ge=0,
        description="Number of leftover sandbox networks removed.",
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Non-fatal errors encountered during resource removal.",
    )


class ExecResult(BaseModel):
    """Structured result of a command executed inside a sandbox."""

    command: list[str] = Field(description="Argument vector of the executed command.")
    exit_code: int | None = Field(
        default=None,
        description="Process exit code; None when the command was terminated by a timeout.",
    )
    stdout: str = Field(default="", description="Standard output captured from the command.")
    stderr: str = Field(default="", description="Standard error captured from the command.")
    duration_seconds: float = Field(
        default=0.0,
        ge=0.0,
        description="Wall-clock execution duration in seconds.",
    )
    timed_out: bool = Field(
        default=False,
        description="True when the command exceeded its timeout and was terminated.",
    )

    @property
    def succeeded(self) -> bool:
        """Return True when the command completed with exit code 0."""
        return self.exit_code == 0


class WorkspaceMount(BaseModel):
    """Explicitly controlled read-only-by-default host workspace binding.

    Construction performs full safety validation of both the host path and the
    container-side target, guaranteeing that arbitrary host files, credential
    stores, SSH keys, ``.env`` files, system paths, and sockets (including the
    Docker socket) are never exposed to sandbox containers.
    """

    host_path: Path = Field(description="Resolved host directory bound into the container.")
    container_path: str = Field(
        default=WORKSPACE_CONTAINER_ROOT,
        description="Absolute container-side mount point restricted to the /workspace subtree.",
    )
    read_only: bool = Field(
        default=True,
        description="Mount the workspace read-only unless explicitly opted out.",
    )

    def model_post_init(self, __context: object) -> None:
        """Normalize and validate both sides of the mount after Pydantic parsing."""
        validated_host = validate_workspace_host_path(self.host_path)
        self.host_path = validated_host
        self.container_path = validate_workspace_container_path(self.container_path)

    def volume_spec(self) -> dict[str, dict[str, str]]:
        """Return the Docker SDK volume mapping for this mount."""
        mode = "ro" if self.read_only else "rw"
        return {str(self.host_path): {"bind": self.container_path, "mode": mode}}


class BaseSandbox(ABC):
    """Abstract base class establishing the interface for all sandbox backends.

    Sandboxes are ephemeral environments used for dynamic security testing.
    Implementations must guarantee resource teardown on normal completion,
    exceptions, timeouts, and cancellation. Prefer the async context manager
    protocol, which invokes :meth:`stop` no matter how the block exits.
    """

    def __init__(self) -> None:
        """Initialize shared lifecycle state for the sandbox instance."""
        self._state: SandboxState = SandboxState.NOT_CREATED
        self._session_id: str = uuid4().hex[:12]

    @property
    def session_id(self) -> str:
        """Return the unique short identifier for this sandbox session."""
        return self._session_id

    @property
    def state(self) -> SandboxState:
        """Return the current lifecycle state of the sandbox."""
        return self._state

    @property
    def is_running(self) -> bool:
        """Return True while the sandbox environment is up and accepting commands."""
        return self._state == SandboxState.RUNNING

    @property
    @abstractmethod
    def backend_name(self) -> str:
        """Return the unique identifier string for this sandbox backend."""
        ...

    @abstractmethod
    async def start(self, workspace_mount: WorkspaceMount | None = None) -> None:
        """Create and start an ephemeral sandbox environment.

        Args:
            workspace_mount: Optional explicitly validated workspace binding.

        Raises:
            SandboxError: If the environment cannot be created or started.
        """
        ...

    @abstractmethod
    async def exec_command(
        self,
        command: Sequence[str],
        *,
        timeout_seconds: float | None = None,
        environment: Mapping[str, str] | None = None,
        workdir: str | None = None,
    ) -> ExecResult:
        """Execute a single command inside the running sandbox with a hard timeout.

        Args:
            command: Argument vector to execute; must be non-empty.
            timeout_seconds: Optional per-command timeout override.
            environment: Optional extra environment variables for the command.
            workdir: Optional working directory override inside the sandbox.

        Returns:
            A structured ExecResult with captured streams and telemetry.

        Raises:
            SandboxNotRunningError: If the sandbox is not currently running.
            SandboxTimeoutError: If the command exceeded its timeout budget.
            SandboxExecutionError: If the backend failed to execute the command.
        """
        ...

    @abstractmethod
    async def stop(self) -> None:
        """Terminate the sandbox and release every backing resource.

        Must be idempotent and safe to call from any state.
        """
        ...

    async def __aenter__(self) -> "BaseSandbox":
        """Start the sandbox and return it for scoped usage."""
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> bool:
        """Guarantee teardown on normal completion, exceptions, timeouts, and cancellation.

        Cleanup errors are logged but never mask exceptions raised by the
        guarded body; the original exception always propagates unchanged.
        """
        try:
            await self.stop()
        except SandboxError as exc:
            logger.warning("Sandbox %s cleanup failed during exit: %s", self.session_id, exc)
        except asyncio.CancelledError:
            logger.warning("Sandbox %s cleanup interrupted by cancellation.", self.session_id)
            raise
        return False
