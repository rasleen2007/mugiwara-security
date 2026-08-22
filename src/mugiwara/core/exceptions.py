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
