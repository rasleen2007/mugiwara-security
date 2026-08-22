"""Factory for initializing sandbox backends."""

from typing import Any

from mugiwara.core.config import SandboxConfig, SandboxMode
from mugiwara.core.exceptions import SandboxNotSupportedError
from mugiwara.sandbox.base import BaseSandbox
from mugiwara.sandbox.docker import DEFAULT_SANDBOX_IMAGE, DockerSandbox
from mugiwara.sandbox.mock import MockSandbox


def get_sandbox(
    config: SandboxConfig,
    *,
    image: str = DEFAULT_SANDBOX_IMAGE,
    client: Any | None = None,
) -> BaseSandbox:
    """Return an initialized sandbox backend instance matching configuration.

    Args:
        config: Sandbox configuration containing the isolation backend mode.
        image: Container image override for the Docker backend.
        client: Optional pre-built Docker client (dependency injection for tests).

    Returns:
        An operational BaseSandbox implementation.

    Raises:
        SandboxNotSupportedError: If a sandbox mode is not implemented in this phase.
    """
    if config.mode == SandboxMode.DOCKER:
        return DockerSandbox(config, image=image, client=client)
    if config.mode == SandboxMode.MOCK:
        return MockSandbox()

    msg = (
        f"Sandbox mode '{config.mode.value}' is deferred to a future phase. "
        f"Use 'docker' for isolated execution or 'mock' for testing."
    )
    raise SandboxNotSupportedError(msg)
