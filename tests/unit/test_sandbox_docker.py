"""Unit tests for the DockerSandbox backend using injected fake Docker clients.

No Docker daemon is required: every test exercises the backend through fake
SDK objects, asserting both behaviour and the exact container hardening
guarantees (non-root, no privileged mode, resource ceilings, isolation).
"""

import asyncio
import sys
import threading
import time
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from mugiwara.core.config import SandboxConfig
from mugiwara.core.exceptions import (
    SandboxCleanupError,
    SandboxExecutionError,
    SandboxImageNotFoundError,
    SandboxNotRunningError,
    SandboxStartError,
    SandboxTimeoutError,
)
from mugiwara.sandbox.base import SandboxState, WorkspaceMount
from mugiwara.sandbox.docker import (
    DEFAULT_SANDBOX_IMAGE,
    MANAGED_LABEL_KEY,
    DockerSandbox,
    build_container_kwargs,
    cleanup_sandbox_resources,
    get_sandbox_status,
)

ExecOutcome = tuple[int, tuple[bytes | None, bytes | None]]


class FakeContainer:
    """Fake docker.models.containers.Container supporting exec_run/remove."""

    def __init__(
        self,
        exec_outcome: ExecOutcome = (0, (b"", b"")),
        exec_delay_seconds: float = 0.0,
        exec_error: Exception | None = None,
        remove_error: Exception | None = None,
    ) -> None:
        self.exec_calls: list[tuple[list[str], dict[str, Any]]] = []
        self.remove_calls: list[bool] = []
        self._exec_outcome = exec_outcome
        self._exec_delay_seconds = exec_delay_seconds
        self._exec_error = exec_error
        self.remove_error = remove_error

    def exec_run(self, cmd: Any, **kwargs: Any) -> ExecOutcome:
        self.exec_calls.append((list(cmd), kwargs))
        if self._exec_delay_seconds > 0:
            time.sleep(self._exec_delay_seconds)
        if self._exec_error is not None:
            raise self._exec_error
        return self._exec_outcome

    def remove(self, force: bool = False) -> None:
        self.remove_calls.append(force)
        if self.remove_error is not None:
            raise self.remove_error


class BlockingFakeContainer(FakeContainer):
    """Fake container whose exec_run blocks until an event is released."""

    def __init__(self) -> None:
        super().__init__()
        self.release_event = threading.Event()

    def exec_run(self, cmd: Any, **kwargs: Any) -> ExecOutcome:
        self.exec_calls.append((list(cmd), kwargs))
        self.release_event.wait(timeout=10.0)
        raise RuntimeError("execution aborted")


class FakeNetwork:
    """Fake docker network object."""

    def __init__(self, name: str, remove_error: Exception | None = None) -> None:
        self.name = name
        self.remove_calls: int = 0
        self.remove_error = remove_error

    def remove(self) -> None:
        self.remove_calls += 1
        if self.remove_error is not None:
            raise self.remove_error


class FakeNetworksApi:
    """Fake client.networks collection."""

    def __init__(self, create_error: Exception | None = None) -> None:
        self.created: list[FakeNetwork] = []
        self.create_kwargs: list[dict[str, Any]] = []
        self.list_filters: list[dict[str, Any]] = []
        self._create_error = create_error

    def create(self, **kwargs: Any) -> FakeNetwork:
        self.create_kwargs.append(kwargs)
        if self._create_error is not None:
            raise self._create_error
        network = FakeNetwork(name=str(kwargs["name"]))
        self.created.append(network)
        return network

    def list(self, filters: dict[str, Any] | None = None) -> list[FakeNetwork]:
        self.list_filters.append(filters or {})
        return list(self.created)


class FakeImagesApi:
    """Fake client.images collection."""

    def __init__(
        self,
        local_missing: bool = False,
        pull_error: Exception | None = None,
    ) -> None:
        self.pulled: list[str] = []
        self._local_missing = local_missing
        self._pull_error = pull_error

    def get(self, name: str) -> dict[str, str]:
        if self._local_missing:
            raise RuntimeError(f"image {name} not found locally")
        return {"id": name}

    def pull(self, name: str) -> dict[str, str]:
        self.pulled.append(name)
        if self._pull_error is not None:
            raise self._pull_error
        return {"id": name}


class FakeContainersApi:
    """Fake client.containers collection."""

    def __init__(
        self,
        run_error: Exception | None = None,
        container: FakeContainer | None = None,
    ) -> None:
        self.created: list[FakeContainer] = []
        self.run_image: str | None = None
        self.run_kwargs: dict[str, Any] = {}
        self.list_filters: list[dict[str, Any]] = []
        self._run_error = run_error
        self._custom_container = container

    def run(self, image: str, **kwargs: Any) -> FakeContainer:
        self.run_image = image
        self.run_kwargs = kwargs
        if self._run_error is not None:
            raise self._run_error
        container = self._custom_container or FakeContainer()
        self.created.append(container)
        return container

    def list(self, filters: dict[str, Any] | None = None) -> list[FakeContainer]:
        self.list_filters.append(filters or {})
        return list(self.created)


class FakeClient:
    """Fake docker.DockerClient covering everything DockerSandbox touches."""

    def __init__(
        self,
        *,
        containers_api: FakeContainersApi | None = None,
        networks_api: FakeNetworksApi | None = None,
        images_api: FakeImagesApi | None = None,
        ping_error: Exception | None = None,
    ) -> None:
        self.containers = containers_api or FakeContainersApi()
        self.networks = networks_api or FakeNetworksApi()
        self.images = images_api or FakeImagesApi()
        self.ping_count = 0
        self._ping_error = ping_error

    def ping(self) -> bool:
        self.ping_count += 1
        if self._ping_error is not None:
            raise self._ping_error
        return True


def install_fake_docker_module(monkeypatch: pytest.MonkeyPatch, client: FakeClient) -> None:
    """Insert a stand-in 'docker' module into sys.modules for lazy-import paths."""
    fake_module = ModuleType("docker")
    fake_module.from_env = lambda: client  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "docker", fake_module)


def _make_sandbox(
    client: FakeClient | None = None,
    config: SandboxConfig | None = None,
) -> DockerSandbox:
    """Build a DockerSandbox bound to a fake client."""
    return DockerSandbox(
        config or SandboxConfig(timeout_seconds=5),
        client=client or FakeClient(),
    )


def test_container_kwargs_security_hardening_defaults() -> None:
    """Assert every mandatory hardening option in generated container kwargs."""
    config = SandboxConfig(memory_limit="1g", cpu_quota=1.5, timeout_seconds=30)
    kwargs = build_container_kwargs(
        config,
        container_name="mugiwara-sbx-test",
        network_name="mugiwara-net-test",
        session_id="test",
    )

    # Privilege boundaries.
    assert kwargs["privileged"] is False
    assert kwargs["user"] == "1000:1000"
    assert kwargs["cap_drop"] == ["ALL"]
    assert kwargs["security_opt"] == ["no-new-privileges:true"]

    # Filesystem containment.
    assert kwargs["read_only"] is True
    assert "/tmp" in kwargs["tmpfs"]
    assert "size=" in kwargs["tmpfs"]["/tmp"]

    # Resource ceilings.
    assert kwargs["mem_limit"] == "1g"
    assert kwargs["memswap_limit"] == "1g"
    assert kwargs["cpu_period"] == 100_000
    assert kwargs["cpu_quota"] == 150_000
    assert kwargs["pids_limit"] > 0

    # Network isolation: dedicated named bridge only; host networking impossible.
    assert kwargs["network"] == "mugiwara-net-test"
    assert kwargs["network"] != "host"

    # No volumes without an explicitly provided workspace mount.
    assert kwargs["volumes"] == {}

    # Ephemeral lifecycle metadata enabling orphan reaping via CLI cleanup.
    assert kwargs["labels"][MANAGED_LABEL_KEY] == "true"
    assert kwargs["detach"] is True
    assert kwargs["command"] == ["sleep", "infinity"]


def test_container_kwargs_workspace_mount_projection(tmp_path: Path) -> None:
    """Verify only validated mounts are projected into volume bindings."""
    project = tmp_path / "project"
    project.mkdir()
    mount = WorkspaceMount(host_path=project)

    kwargs = build_container_kwargs(
        SandboxConfig(),
        container_name="mugiwara-sbx-ws",
        network_name="mugiwara-net-ws",
        session_id="ws",
        workspace_mount=mount,
    )

    expected_host = str(project.resolve())
    assert kwargs["volumes"] == {expected_host: {"bind": "/workspace", "mode": "ro"}}
    assert kwargs["working_dir"] == "/workspace"
    assert "docker.sock" not in str(kwargs["volumes"])


async def test_start_provisions_internal_bridge_and_hardened_container() -> None:
    """Verify start() provisions an internal bridge network plus hardened container."""
    client = FakeClient()
    sandbox = _make_sandbox(client)

    await sandbox.start()

    assert sandbox.state == SandboxState.RUNNING
    assert sandbox.is_running is True
    assert sandbox.backend_name == "docker"

    network_kwargs = client.networks.create_kwargs[-1]
    assert network_kwargs["driver"] == "bridge"
    assert network_kwargs["internal"] is True
    assert client.networks.created[0].name.startswith("mugiwara-net-")

    run_kwargs = client.containers.run_kwargs
    assert client.containers.run_image == DEFAULT_SANDBOX_IMAGE
    assert run_kwargs["privileged"] is False
    assert run_kwargs["user"] == "1000:1000"
    assert run_kwargs["cap_drop"] == ["ALL"]
    assert run_kwargs["read_only"] is True
    assert run_kwargs["network"].startswith("mugiwara-net-")
    assert run_kwargs["name"].startswith("mugiwara-sbx-")


async def test_start_binds_only_validated_workspace_mount(tmp_path: Path) -> None:
    """Verify start() forwards exactly one validated read-only workspace bind."""
    client = FakeClient()
    sandbox = _make_sandbox(client)
    project = tmp_path / "target-app"
    project.mkdir()
    mount = WorkspaceMount(host_path=project)

    await sandbox.start(workspace_mount=mount)

    volumes = client.containers.run_kwargs["volumes"]
    assert list(volumes.keys()) == [str(project.resolve())]
    bind_spec = volumes[str(project.resolve())]
    assert bind_spec["bind"] == "/workspace"
    assert bind_spec["mode"] == "ro"


async def test_exec_command_returns_decoded_streams() -> None:
    """Verify successful execution decodes demultiplexed streams and telemetry."""
    fake_container = FakeContainer(exec_outcome=(0, (b"hello stdout", b"hello stderr")))
    client = FakeClient(containers_api=FakeContainersApi(container=fake_container))

    sandbox = _make_sandbox(client)
    await sandbox.start()
    result = await sandbox.exec_command(["echo", "hello"])

    assert result.exit_code == 0
    assert result.stdout == "hello stdout"
    assert result.stderr == "hello stderr"
    assert result.timed_out is False
    assert result.succeeded is True
    assert result.duration_seconds >= 0.0
    recorded_cmd, recorded_kwargs = fake_container.exec_calls[0]
    assert recorded_cmd == ["echo", "hello"]
    assert recorded_kwargs["demux"] is True


async def test_exec_command_forwards_environment_and_workdir() -> None:
    """Verify optional environment/workdir parameters reach the exec call."""
    fake_container = FakeContainer(exec_outcome=(3, (None, b"boom")))
    client = FakeClient(containers_api=FakeContainersApi(container=fake_container))
    sandbox = _make_sandbox(client)
    await sandbox.start()

    result = await sandbox.exec_command(
        ["python", "-V"],
        environment={"POC_MODE": "canary"},
        workdir="/workspace",
    )

    _, recorded_kwargs = fake_container.exec_calls[0]
    assert recorded_kwargs["environment"] == {"POC_MODE": "canary"}
    assert recorded_kwargs["workdir"] == "/workspace"
    assert result.exit_code == 3
    assert result.stdout == ""
    assert result.succeeded is False


async def test_exec_command_requires_running_sandbox() -> None:
    """Verify command submission before start raises SandboxNotRunningError."""
    sandbox = _make_sandbox()
    with pytest.raises(SandboxNotRunningError):
        await sandbox.exec_command(["id"])


async def test_exec_command_rejects_empty_vector() -> None:
    """Verify empty argv is rejected before touching the backend."""
    sandbox = _make_sandbox()
    await sandbox.start()
    with pytest.raises(SandboxExecutionError, match="empty"):
        await sandbox.exec_command([])


async def test_exec_command_timeout_kills_and_cleans_session() -> None:
    """Verify timeout terminates the session and removes all resources."""
    slow_container = FakeContainer(exec_delay_seconds=2.0)
    client = FakeClient(containers_api=FakeContainersApi(container=slow_container))
    sandbox = _make_sandbox(client)
    await sandbox.start()
    network = client.networks.created[0]

    with pytest.raises(SandboxTimeoutError, match="timeout"):
        await sandbox.exec_command(["sleep", "999"], timeout_seconds=0.05)

    assert sandbox.state == SandboxState.STOPPED
    assert slow_container.remove_calls == [True]
    assert network.remove_calls == 1


async def test_exec_command_wraps_backend_failures() -> None:
    """Verify unexpected SDK errors are wrapped into SandboxExecutionError."""
    broken_container = FakeContainer(exec_error=RuntimeError("socket closed"))
    client = FakeClient(containers_api=FakeContainersApi(container=broken_container))
    sandbox = _make_sandbox(client)
    await sandbox.start()

    with pytest.raises(SandboxExecutionError, match="socket closed"):
        await sandbox.exec_command(["whoami"])


async def test_stop_is_idempotent_and_force_removes_resources() -> None:
    """Verify stop() removes resources once and tolerates repeated calls."""
    client = FakeClient()
    sandbox = _make_sandbox(client)
    await sandbox.start()
    container = client.containers.created[0]
    network = client.networks.created[0]

    await sandbox.stop()
    await sandbox.stop()

    assert container.remove_calls == [True]
    assert network.remove_calls == 1
    assert sandbox.state == SandboxState.STOPPED


async def test_stop_tolerates_already_removed_resources() -> None:
    """Verify NotFound-style failures during teardown are treated as success."""
    vanishing_container = FakeContainer(remove_error=RuntimeError("container not found"))
    vanishing_network = FakeNetwork("mugiwara-net-gone", remove_error=RuntimeError("not found"))
    client = FakeClient(
        containers_api=FakeContainersApi(container=vanishing_container),
        networks_api=FakeNetworksApi(),
    )
    sandbox = _make_sandbox(client)
    await sandbox.start()
    client.networks.created.clear()
    client.networks.created.append(vanishing_network)

    await sandbox.stop()

    assert sandbox.state == SandboxState.STOPPED


async def test_stop_aggregates_teardown_failures() -> None:
    """Verify genuine teardown failures surface as SandboxCleanupError."""
    busy_container = FakeContainer(remove_error=RuntimeError("device busy"))
    client = FakeClient(
        containers_api=FakeContainersApi(container=busy_container),
        networks_api=FakeNetworksApi(),
    )
    sandbox = _make_sandbox(client)
    await sandbox.start()
    session_network = client.networks.created[0]
    session_network.remove_error = RuntimeError("conflict")

    with pytest.raises(SandboxCleanupError) as exc_info:
        await sandbox.stop()

    message = str(exc_info.value)
    assert "device busy" in message
    assert "conflict" in message
    assert sandbox.state == SandboxState.STOPPED


async def test_start_failure_after_network_creation_leaks_nothing() -> None:
    """Verify image resolution failure triggers partial-resource cleanup."""
    client = FakeClient(
        images_api=FakeImagesApi(
            local_missing=True,
            pull_error=RuntimeError("registry offline"),
        )
    )
    sandbox = _make_sandbox(client)

    with pytest.raises(SandboxImageNotFoundError, match="registry offline"):
        await sandbox.start()

    assert sandbox.state != SandboxState.RUNNING
    assert len(client.containers.created) == 0
    assert client.networks.created[0].remove_calls == 1


async def test_start_failure_during_container_creation_leaks_nothing() -> None:
    """Verify container creation failure removes the provisioned network."""
    client = FakeClient(containers_api=FakeContainersApi(run_error=RuntimeError("port taken")))
    sandbox = _make_sandbox(client)

    with pytest.raises(SandboxStartError, match="port taken"):
        await sandbox.start()

    assert len(client.containers.created) == 0
    assert client.networks.created[0].remove_calls == 1


async def test_context_manager_normal_completion_cleans_up() -> None:
    """Verify async-with teardown on normal completion."""
    client = FakeClient()
    sandbox = _make_sandbox(client)

    async with sandbox as entered:
        assert entered is sandbox
        await entered.exec_command(["true"])

    assert sandbox.state == SandboxState.STOPPED
    assert client.containers.created[0].remove_calls == [True]
    assert client.networks.created[0].remove_calls == 1


async def test_context_manager_body_exception_propagates_and_cleans_up() -> None:
    """Verify async-with teardown when the guarded body raises."""
    client = FakeClient()
    sandbox = _make_sandbox(client)

    with pytest.raises(RuntimeError, match="scan failed"):  # noqa: PT012 - multi-statement body
        async with sandbox:
            await sandbox.exec_command(["probe"])
            raise RuntimeError("scan failed")

    assert sandbox.state == SandboxState.STOPPED
    assert client.containers.created[0].remove_calls == [True]
    assert client.networks.created[0].remove_calls == 1


async def test_cancellation_of_running_command_tears_down_session() -> None:
    """Verify task cancellation during execution still guarantees teardown."""
    blocking_container = BlockingFakeContainer()
    client = FakeClient(containers_api=FakeContainersApi(container=blocking_container))
    sandbox = _make_sandbox(client)
    await sandbox.start()

    task = asyncio.ensure_future(sandbox.exec_command(["long", "probe"]))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    blocking_container.release_event.set()
    await asyncio.sleep(0)

    assert sandbox.state == SandboxState.STOPPED
    assert blocking_container.remove_calls == [True]
    assert client.networks.created[0].remove_calls == 1


async def test_double_start_is_rejected() -> None:
    """Verify starting a running sandbox raises SandboxStartError."""
    sandbox = _make_sandbox()
    await sandbox.start()
    with pytest.raises(SandboxStartError, match="already running"):
        await sandbox.start()


def test_is_docker_available_true_with_healthy_daemon(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify availability probe succeeds when the daemon answers ping."""
    install_fake_docker_module(monkeypatch, FakeClient())
    assert DockerSandbox.is_docker_available() is True


def test_is_docker_available_false_when_ping_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify availability probe reports unreachable daemons as unavailable."""
    unhealthy = FakeClient(ping_error=RuntimeError("connection refused"))
    install_fake_docker_module(monkeypatch, unhealthy)
    assert DockerSandbox.is_docker_available() is False


def test_get_sandbox_status_reports_managed_resources(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify status aggregation counts managed containers and networks."""
    client = FakeClient()
    client.containers.created.append(FakeContainer())
    client.networks.created.append(FakeNetwork("mugiwara-net-orphan"))
    install_fake_docker_module(monkeypatch, client)

    status = get_sandbox_status()

    assert status.backend == "docker"
    assert status.available is True
    assert status.managed_containers == 1
    assert status.managed_networks == 1


def test_get_sandbox_status_unreachable_daemon(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify daemon connectivity problems degrade into an unavailable status."""
    install_fake_docker_module(monkeypatch, FakeClient(ping_error=RuntimeError("daemon down")))

    status = get_sandbox_status()

    assert status.available is False
    assert "daemon down" in status.message


def test_cleanup_sandbox_resources_removes_labeled_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify cleanup sweep removes managed containers and networks."""
    orphan_container = FakeContainer()
    orphan_network = FakeNetwork("mugiwara-net-orphan")
    client = FakeClient()
    client.containers.created.append(orphan_container)
    client.networks.created.append(orphan_network)
    install_fake_docker_module(monkeypatch, client)

    report = cleanup_sandbox_resources()

    assert report.containers_removed == 1
    assert report.networks_removed == 1
    assert report.errors == []
    assert orphan_container.remove_calls == [True]
    assert orphan_network.remove_calls == 1
    assert client.containers.list_filters[0] == {"label": f"{MANAGED_LABEL_KEY}=true"}
    assert client.networks.list_filters[0] == {"label": f"{MANAGED_LABEL_KEY}=true"}


def test_cleanup_sandbox_resources_collects_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify individual removal failures are reported without aborting the sweep."""
    stubborn = FakeContainer(remove_error=RuntimeError("cannot remove"))
    healthy = FakeContainer()
    client = FakeClient(containers_api=FakeContainersApi())
    client.containers.created.extend([stubborn, healthy])
    install_fake_docker_module(monkeypatch, client)

    report = cleanup_sandbox_resources()

    assert report.containers_removed == 1
    assert len(report.errors) == 1
    assert "cannot remove" in report.errors[0]
