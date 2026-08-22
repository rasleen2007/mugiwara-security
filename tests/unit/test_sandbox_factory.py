"""Unit tests for the sandbox backend factory."""

import pytest

from mugiwara.core.config import SandboxConfig, SandboxMode
from mugiwara.core.exceptions import SandboxNotSupportedError
from mugiwara.sandbox.docker import DockerSandbox
from mugiwara.sandbox.factory import get_sandbox
from mugiwara.sandbox.mock import MockSandbox
from tests.unit.test_sandbox_docker import FakeClient


def test_factory_builds_docker_sandbox() -> None:
    """Verify docker mode produces a DockerSandbox bound to the injected client."""
    client = FakeClient()
    sandbox = get_sandbox(SandboxConfig(mode=SandboxMode.DOCKER), client=client)

    assert isinstance(sandbox, DockerSandbox)
    assert sandbox.backend_name == "docker"
    # Dependency injection must be honoured so tests never need a daemon.
    sandbox._ensure_client()
    assert client.ping_count == 0  # client resolution is lazy; no daemon contact yet


def test_factory_builds_mock_sandbox() -> None:
    """Verify mock mode produces a MockSandbox."""
    sandbox = get_sandbox(SandboxConfig(mode=SandboxMode.MOCK))

    assert isinstance(sandbox, MockSandbox)
    assert sandbox.backend_name == "mock"


def test_factory_rejects_none_mode() -> None:
    """Verify unsandboxed execution is never silently provided."""
    with pytest.raises(SandboxNotSupportedError) as exc_info:
        get_sandbox(SandboxConfig(mode=SandboxMode.NONE))

    assert "deferred" in str(exc_info.value)
