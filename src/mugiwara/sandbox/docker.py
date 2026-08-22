"""Docker-backed ephemeral sandbox runtime with strict safety guardrails.

Every container created by this module is hardened by construction:

- Non-root execution as ``1000:1000``.
- Never privileged, never host networking, never a Docker socket mount.
- All Linux capabilities dropped and ``no-new-privileges`` enforced.
- Read-only root filesystem with a bounded ``/tmp`` tmpfs.
- Hard memory/CPU/PIDs quotas to contain runaway or fork-bombing processes.
- Dedicated per-session *internal* bridge network blocking outbound internet.
- Explicitly validated workspace mounts restricted to the ``/workspace`` subtree.

Containers are ephemeral: they exist for a single session and are force-removed
on normal completion, exceptions, timeouts, and task cancellation. The Docker
SDK is imported lazily and clients can be injected, so unit tests never require
a running Docker daemon.
"""

import asyncio
import logging
import time
from collections.abc import Mapping, Sequence
from typing import Any

from mugiwara.core.config import SandboxConfig
from mugiwara.core.exceptions import (
    SandboxCleanupError,
    SandboxConnectionError,
    SandboxError,
    SandboxExecutionError,
    SandboxImageNotFoundError,
    SandboxNotRunningError,
    SandboxStartError,
    SandboxTimeoutError,
)
from mugiwara.sandbox.base import (
    WORKSPACE_CONTAINER_ROOT,
    BaseSandbox,
    CleanupReport,
    ExecResult,
    SandboxState,
    SandboxStatus,
    WorkspaceMount,
)

logger = logging.getLogger(__name__)

DEFAULT_SANDBOX_IMAGE = "python:3.12-slim"
SANDBOX_USER = "1000:1000"
SANDBOX_KEEPALIVE_COMMAND = ("sleep", "infinity")
CONTAINER_NAME_PREFIX = "mugiwara-sbx-"
NETWORK_NAME_PREFIX = "mugiwara-net-"
MANAGED_LABEL_KEY = "mugiwara.managed"
SESSION_LABEL_KEY = "mugiwara.session_id"
MANAGED_LABEL_SELECTOR = f"{MANAGED_LABEL_KEY}=true"
CPU_PERIOD = 100_000
SANDBOX_PIDS_LIMIT = 256
SANDBOX_TMPFS = {"/tmp": "rw,noexec,nosuid,size=64m"}


def _decode_stream(data: bytes | None) -> str:
    """Decode a Docker exec output stream into text, tolerating None values."""
    if not data:
        return ""
    return data.decode("utf-8", errors="replace")


def _is_not_found_error(exc: BaseException) -> bool:
    """Return True when an SDK exception indicates an already-removed resource."""
    if type(exc).__name__ == "NotFound":
        return True
    return "not found" in str(exc).lower()


def build_container_kwargs(
    config: SandboxConfig,
    *,
    container_name: str,
    network_name: str,
    session_id: str,
    workspace_mount: WorkspaceMount | None = None,
) -> dict[str, Any]:
    """Build hardened Docker container creation keyword arguments.

    This pure function centralizes every security-relevant container option so
    unit tests can assert the exact guardrails without touching Docker.

    Args:
        config: Sandbox configuration providing resource limits.
        container_name: Unique ephemeral container name.
        network_name: Name of the dedicated internal bridge network to attach.
        session_id: Unique sandbox session identifier used for labels.
        workspace_mount: Optional validated workspace binding.

    Returns:
        Keyword arguments suitable for ``client.containers.run(image, **kwargs)``.
    """
    volumes = workspace_mount.volume_spec() if workspace_mount is not None else {}
    working_dir = (
        workspace_mount.container_path if workspace_mount is not None else WORKSPACE_CONTAINER_ROOT
    )
    return {
        # Lifecycle: detached keep-alive shell so commands can be exec'd per call.
        "name": container_name,
        "command": list(SANDBOX_KEEPALIVE_COMMAND),
        "detach": True,
        # Privilege boundaries: never privileged, non-root, no capability set.
        "privileged": False,
        "user": SANDBOX_USER,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        # Filesystem containment: immutable root plus bounded scratch space.
        "read_only": True,
        "tmpfs": dict(SANDBOX_TMPFS),
        # Resource ceilings: memory (and identical swap ceiling), CPU quota, PIDs.
        "mem_limit": config.memory_limit,
        "memswap_limit": config.memory_limit,
        "cpu_period": CPU_PERIOD,
        "cpu_quota": int(config.cpu_quota * CPU_PERIOD),
        "pids_limit": SANDBOX_PIDS_LIMIT,
        # Network isolation: dedicated internal bridge only; host networking is
        # structurally impossible here because 'network' always names our network.
        "network": network_name,
        # Workspace: only explicitly validated mounts are ever projected.
        "volumes": volumes,
        "working_dir": working_dir,
        # Ownership metadata enabling `mugiwara sandbox cleanup` reaping.
        "labels": {
            MANAGED_LABEL_KEY: "true",
            SESSION_LABEL_KEY: session_id,
        },
    }


def _force_remove_container(container: Any) -> None:
    """Force-remove a container, tolerating resources that already disappeared."""
    try:
        container.remove(force=True)
    except Exception as exc:
        if _is_not_found_error(exc):
            return
        raise


def _remove_network(network: Any) -> None:
    """Remove a network, tolerating resources that already disappeared."""
    try:
        network.remove()
    except Exception as exc:
        if _is_not_found_error(exc):
            return
        raise


class DockerSandbox(BaseSandbox):
    """Ephemeral single-session Docker sandbox with guaranteed teardown."""

    def __init__(
        self,
        config: SandboxConfig,
        *,
        image: str = DEFAULT_SANDBOX_IMAGE,
        client: Any | None = None,
    ) -> None:
        """Initialize the sandbox runtime.

        Args:
            config: Sandbox configuration controlling limits and timeouts.
            image: Container image used for the ephemeral environment.
            client: Optional pre-built Docker client (dependency injection for tests).
        """
        super().__init__()
        self._config = config
        self.image = image
        self._injected_client = client
        self._client: Any | None = None
        self._container: Any | None = None
        self._network: Any | None = None

    @property
    def backend_name(self) -> str:
        """Return backend identifier string."""
        return "docker"

    @property
    def container_name(self) -> str:
        """Return the deterministic ephemeral container name for this session."""
        return f"{CONTAINER_NAME_PREFIX}{self.session_id}"

    @property
    def network_name(self) -> str:
        """Return the deterministic isolated network name for this session."""
        return f"{NETWORK_NAME_PREFIX}{self.session_id}"

    @classmethod
    def is_docker_available(cls) -> bool:
        """Return True when the local Docker daemon accepts connections."""
        probe = cls(SandboxConfig())
        try:
            probe._ensure_client()
        except SandboxConnectionError:
            return False
        return True

    def _labels(self) -> dict[str, str]:
        """Return ownership labels applied to all resources of this session."""
        return {MANAGED_LABEL_KEY: "true", SESSION_LABEL_KEY: self.session_id}

    def _ensure_client(self) -> Any:
        """Lazily resolve the Docker SDK client, wrapping failures in typed errors.

        Raises:
            SandboxConnectionError: If the SDK is missing or the daemon unreachable.
        """
        if self._client is not None:
            return self._client
        if self._injected_client is not None:
            self._client = self._injected_client
            return self._client

        try:
            import docker  # type: ignore[import-untyped]
        except ImportError as exc:
            msg = "The Docker SDK is not installed; Docker sandboxes are unavailable."
            raise SandboxConnectionError(msg) from exc

        try:
            client = docker.from_env()
            client.ping()
        except Exception as exc:
            msg = f"Docker daemon is not reachable: {exc}"
            raise SandboxConnectionError(msg) from exc

        self._client = client
        return client

    def _create_network(self, client: Any) -> Any:
        """Create the dedicated internal bridge network isolating this session."""
        try:
            return client.networks.create(
                name=self.network_name,
                driver="bridge",
                internal=True,
                labels=self._labels(),
            )
        except Exception as exc:
            msg = f"Failed to create isolated bridge network '{self.network_name}': {exc}"
            raise SandboxStartError(msg) from exc

    async def _cleanup_partial(self, container: Any | None, network: Any | None) -> None:
        """Best-effort removal of resources created by a failed :meth:`start`."""
        try:
            await asyncio.to_thread(self._teardown_sync, container, network)
        except Exception as cleanup_exc:  # noqa: BLE001 - best-effort path
            logger.warning(
                "Partial cleanup after failed start of sandbox '%s': %s",
                self.session_id,
                cleanup_exc,
            )

    def _ensure_image(self, client: Any) -> None:
        """Resolve the sandbox image locally, pulling it on first use."""
        try:
            client.images.get(self.image)
            return
        except Exception:
            logger.info("Sandbox image '%s' not present locally; pulling.", self.image)
        try:
            client.images.pull(self.image)
        except Exception as exc:
            msg = (
                f"Sandbox image '{self.image}' is unavailable locally and could not "
                f"be pulled from any registry: {exc}"
            )
            raise SandboxImageNotFoundError(msg) from exc

    async def start(self, workspace_mount: WorkspaceMount | None = None) -> None:
        """Create and boot the hardened ephemeral container and its network.

        Args:
            workspace_mount: Optional explicitly validated workspace binding.

        Raises:
            SandboxStartError: If the sandbox is misused or creation fails.
            SandboxImageNotFoundError: If the image cannot be resolved.
            SandboxWorkspaceError: If the requested mount violates safety rules.
        """
        if self._state == SandboxState.RUNNING:
            msg = f"Docker sandbox '{self.session_id}' is already running."
            raise SandboxStartError(msg)

        client = self._ensure_client()
        created_network: Any | None = None
        created_container: Any | None = None
        try:
            created_network = await asyncio.to_thread(self._create_network, client)
            await asyncio.to_thread(self._ensure_image, client)
            kwargs = build_container_kwargs(
                self._config,
                container_name=self.container_name,
                network_name=self.network_name,
                session_id=self.session_id,
                workspace_mount=workspace_mount,
            )
            created_container = await asyncio.to_thread(client.containers.run, self.image, **kwargs)
        except asyncio.CancelledError:
            await self._cleanup_partial(created_container, created_network)
            raise
        except SandboxError:
            # Typed sandbox failures (image resolution, network creation, ...)
            # already carry precise context; guarantee no partial leaks, then propagate.
            await self._cleanup_partial(created_container, created_network)
            raise
        except Exception as exc:
            await self._cleanup_partial(created_container, created_network)
            msg = f"Failed to start Docker sandbox '{self.session_id}': {exc}"
            raise SandboxStartError(msg) from exc

        self._network = created_network
        self._container = created_container
        self._state = SandboxState.RUNNING
        logger.info("Started sandbox '%s' (container=%s).", self.session_id, self.container_name)

    async def exec_command(
        self,
        command: Sequence[str],
        *,
        timeout_seconds: float | None = None,
        environment: Mapping[str, str] | None = None,
        workdir: str | None = None,
    ) -> ExecResult:
        """Execute one monitored command inside the sandbox with a hard timeout.

        On timeout the entire session container is terminated and removed before
        raising, guaranteeing that no runaway process survives the deadline.
        On cancellation the session is torn down as well; the original
        :class:`asyncio.CancelledError` still propagates to the caller.
        """
        argv = list(command)
        if not argv:
            msg = "Command argument vector must not be empty."
            raise SandboxExecutionError(msg)
        if self._state != SandboxState.RUNNING or self._container is None:
            msg = f"Docker sandbox '{self.session_id}' is not running."
            raise SandboxNotRunningError(msg)

        effective_timeout = (
            float(timeout_seconds)
            if timeout_seconds is not None
            else float(self._config.timeout_seconds)
        )
        container = self._container
        started_at = time.monotonic()
        try:
            outcome = await asyncio.wait_for(
                asyncio.to_thread(
                    container.exec_run,
                    argv,
                    demux=True,
                    environment=dict(environment) if environment is not None else None,
                    workdir=workdir,
                ),
                timeout=effective_timeout,
            )
        except asyncio.TimeoutError as exc:
            await self.stop()
            msg = (
                f"Command {argv!r} exceeded the {effective_timeout:.1f}s execution "
                f"timeout and was terminated along with sandbox '{self.session_id}'."
            )
            raise SandboxTimeoutError(msg) from exc
        except asyncio.CancelledError:
            container_ref = self._container
            network_ref = self._network
            self._container = None
            self._network = None
            self._state = SandboxState.STOPPED
            try:
                await asyncio.shield(
                    asyncio.to_thread(self._teardown_sync, container_ref, network_ref)
                )
            except Exception as teardown_exc:
                logger.warning(
                    "Teardown after cancelled command in sandbox '%s': %s",
                    self.session_id,
                    teardown_exc,
                )
            raise
        except Exception as exc:
            msg = f"Failed executing command {argv!r} in sandbox '{self.session_id}': {exc}"
            raise SandboxExecutionError(msg) from exc

        duration = max(0.0, time.monotonic() - started_at)
        exit_code, streams = outcome
        stdout_data, stderr_data = streams if streams is not None else (None, None)
        return ExecResult(
            command=argv,
            exit_code=int(exit_code),
            stdout=_decode_stream(stdout_data),
            stderr=_decode_stream(stderr_data),
            duration_seconds=duration,
        )

    def _teardown_sync(
        self,
        container: Any | None = None,
        network: Any | None = None,
    ) -> None:
        """Remove the session container and network synchronously.

        Defaults to the currently registered session resources. Every removal
        step runs even if earlier steps fail; collected failures surface as a
        single aggregated error afterwards.
        """
        target_container = container if container is not None else self._container
        target_network = network if network is not None else self._network
        errors: list[str] = []
        if target_container is not None:
            try:
                _force_remove_container(target_container)
            except Exception as exc:
                errors.append(f"container removal failed: {exc}")
        if target_network is not None:
            try:
                _remove_network(target_network)
            except Exception as exc:
                errors.append(f"network removal failed: {exc}")
        if errors:
            msg = "; ".join(errors)
            raise RuntimeError(msg)

    async def stop(self) -> None:
        """Terminate and remove all backing resources; idempotent.

        Removal executes inside a worker thread: even if the awaiting task is
        cancelled mid-teardown, the thread completes and resources are removed.
        """
        container = self._container
        network = self._network
        self._container = None
        self._network = None
        if self._state != SandboxState.STOPPED:
            self._state = SandboxState.STOPPED

        if container is None and network is None:
            return

        try:
            await asyncio.to_thread(self._teardown_sync, container, network)
        except asyncio.CancelledError:
            logger.warning(
                "Sandbox '%s' teardown interrupted by cancellation; worker thread continues.",
                self.session_id,
            )
            raise
        except Exception as exc:
            msg = f"Failed to tear down sandbox '{self.session_id}': {exc}"
            raise SandboxCleanupError(msg) from exc
        logger.info("Stopped sandbox '%s'.", self.session_id)


def get_sandbox_status() -> SandboxStatus:
    """Collect a diagnostic snapshot of the local Docker sandbox backend.

    Never raises: connectivity problems are reported through the returned model.
    """
    try:
        import docker
    except ImportError:
        return SandboxStatus(
            backend="docker",
            available=False,
            message="The Docker SDK package is not installed.",
        )
    try:
        client = docker.from_env()
        client.ping()
        containers = client.containers.list(filters={"label": MANAGED_LABEL_SELECTOR})
        networks = client.networks.list(filters={"label": MANAGED_LABEL_SELECTOR})
    except Exception as exc:
        return SandboxStatus(
            backend="docker",
            available=False,
            message=f"Docker daemon is not reachable: {exc}",
        )
    return SandboxStatus(
        backend="docker",
        available=True,
        message="Docker daemon is reachable.",
        managed_containers=len(containers),
        managed_networks=len(networks),
    )


def cleanup_sandbox_resources() -> CleanupReport:
    """Force-remove all leftover Mugiwara-managed containers and networks.

    Intended for the ``mugiwara sandbox cleanup`` CLI command to reap resources
    orphaned by crashed sessions. Never raises; individual failures are listed
    in :attr:`CleanupReport.errors`.
    """
    report = CleanupReport()
    try:
        import docker
    except ImportError:
        report.errors.append("The Docker SDK package is not installed.")
        return report
    try:
        client = docker.from_env()
        client.ping()
        containers = list(client.containers.list(filters={"label": MANAGED_LABEL_SELECTOR}))
        networks = list(client.networks.list(filters={"label": MANAGED_LABEL_SELECTOR}))
    except Exception as exc:
        report.errors.append(f"Docker daemon is not reachable: {exc}")
        return report

    for container in containers:
        try:
            _force_remove_container(container)
            report.containers_removed += 1
        except Exception as exc:
            report.errors.append(f"Failed to remove container: {exc}")
    for network in networks:
        try:
            _remove_network(network)
            report.networks_removed += 1
        except Exception as exc:
            report.errors.append(f"Failed to remove network: {exc}")
    return report
