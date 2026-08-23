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


class RemoteProviderNotAuthorizedError(ProviderError):
    """Raised when source-code egress to a non-local endpoint is not authorized.

    The user must explicitly set ``llm.allow_remote: true`` before any
    request is allowed to leave the local machine.
    """


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


class SandboxImageBuildError(SandboxError):
    """Raised when a dependency-aware sandbox image cannot be safely built.

    Covers invalid or oversized dependency manifests, build-time failures,
    and hard build timeouts. Verification degrades explicitly instead of
    silently running against an image that lacks the project's dependencies.
    """


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


class AgentError(MugiwaraError):
    """Base exception for all security agent errors."""


class AgentExecutionError(AgentError):
    """Raised when an agent fails during its analysis or LLM interaction."""


class PromptRenderError(AgentError):
    """Raised when a prompt template is missing, malformed, or cannot be rendered."""


class TokenBudgetExceededError(AgentError):
    """Raised when an LLM call would exceed the configured session token budget."""


class TargetPathError(AgentError):
    """Raised when a scan target path is missing, invalid, or escapes its allowed root."""


class VerificationError(AgentError):
    """Base exception for dynamic exploit verification failures."""


class PocRejectedError(VerificationError):
    """Raised when a synthesized PoC script fails static safety screening."""


class VerificationUnavailableError(VerificationError):
    """Raised when dynamic verification is requested without an operational sandbox."""


class IntakeError(MugiwaraError):
    """Base exception for source-project intake failures."""


class TargetNotAvailableError(IntakeError):
    """Raised when the supplied project path is missing or is not a directory."""


class ArchiveRejectedError(IntakeError):
    """Raised when an uploaded archive fails a safety or limit check."""


class ReportStoreError(MugiwaraError):
    """Base exception for persisted report storage failures."""


class ReportNotFoundError(ReportStoreError):
    """Raised when a requested report does not exist in the store."""


class ReportPathEscapeError(ReportStoreError):
    """Raised when a report reference resolves outside the store directory."""


class ReportFormatError(ReportStoreError):
    """Raised when a stored report file is not valid JSON."""


class UnsupportedSchemaError(ReportStoreError):
    """Raised when a file carries an unknown schema name or version."""


class ReportInvalidContentsError(ReportStoreError):
    """Raised when a stored file is JSON but not a valid scan-report envelope."""


class ReportTargetMismatchError(ReportStoreError):
    """Raised when a remediation project root does not match the stored report.

    Reports are bound to the exact directory they scanned; remediating a
    different tree with stored findings is refused so patches can never be
    steered into an unintended project.
    """
