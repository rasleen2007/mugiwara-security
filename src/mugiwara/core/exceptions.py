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
