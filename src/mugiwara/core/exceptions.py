"""Core exceptions for Mugiwara Security."""


class MugiwaraError(Exception):
    """Base exception for all Mugiwara Security errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ConfigurationError(MugiwaraError):
    """Raised when there is an issue with application configuration."""


class ConfigFileNotFoundError(ConfigurationError):
    """Raised when a specified configuration file does not exist."""


class ConfigValidationError(ConfigurationError):
    """Raised when configuration values fail validation constraints."""


class ProviderError(MugiwaraError):
    """Base exception for all LLM provider errors."""


class ProviderNotSupportedError(ProviderError):
    """Raised when an unsupported or un-implemented provider type is requested."""


class ProviderAuthenticationError(ProviderError):
    """Raised when provider API authentication fails or credentials are missing."""


class ProviderExecutionError(ProviderError):
    """Raised when an LLM completion or structured generation fails during runtime."""


class SandboxError(MugiwaraError):
    """Base exception for all sandbox execution errors."""


class SandboxNotSupportedError(SandboxError):
    """Raised when an unsupported or un-implemented sandbox backend is requested."""


class SandboxConnectionError(SandboxError):
    """Raised when the sandbox backend (e.g. Docker daemon) cannot be reached."""


class SandboxImageNotFoundError(SandboxError):
    """Raised when the sandbox container image is unavailable locally and remotely."""


class SandboxStartError(SandboxError):
    """Raised when sandbox environment creation or startup fails."""


class SandboxNotRunningError(SandboxError):
    """Raised when a command is submitted to a sandbox that is not running."""


class SandboxExecutionError(SandboxError):
    """Raised when command execution inside the sandbox fails."""


class SandboxTimeoutError(SandboxExecutionError):
    """Raised when a command exceeds its execution timeout and is terminated."""


class SandboxWorkspaceError(SandboxError):
    """Raised when a workspace mount request violates sandbox safety boundaries."""


class SandboxCleanupError(SandboxError):
    """Raised when sandbox resource teardown fails after all removal attempts."""
