"""Typed configuration management system for Mugiwara Security."""

from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, SecretStr, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from mugiwara.core.exceptions import (
    ConfigFileNotFoundError,
    ConfigValidationError,
)


class LLMProviderType(str, Enum):
    """Supported LLM provider types."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    OLLAMA = "ollama"
    MOCK = "mock"


class ScanProfile(str, Enum):
    """Security scan profile options."""

    FAST = "fast"
    STANDARD = "standard"
    DEEP = "deep"


class SandboxMode(str, Enum):
    """Sandbox execution environment modes."""

    DOCKER = "docker"
    MOCK = "mock"
    NONE = "none"


class OutputFormat(str, Enum):
    """Output reporting formats."""

    TEXT = "text"
    JSON = "json"
    SARIF = "sarif"
    MARKDOWN = "markdown"


class LogLevel(str, Enum):
    """Supported logging severity levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LLMConfig(BaseModel):
    """Configuration settings for LLM interactions."""

    provider: LLMProviderType = Field(
        default=LLMProviderType.OLLAMA,
        description=(
            "LLM provider backend for agent reasoning. Defaults to the local "
            "Ollama daemon so a fresh install needs no cloud API key."
        ),
    )
    model: str = Field(
        default="llama3.2",
        min_length=1,
        description="Model identifier or name for the selected provider.",
    )
    temperature: float = Field(
        default=0.0,
        ge=0.0,
        le=2.0,
        description="Sampling temperature between 0.0 (deterministic) and 2.0 (creative).",
    )
    max_tokens: int | None = Field(
        default=4096,
        gt=0,
        description="Maximum number of tokens to generate per completion.",
    )
    timeout_seconds: float = Field(
        default=60.0,
        gt=0.0,
        description="HTTP request timeout in seconds for LLM calls.",
    )
    api_key: SecretStr | None = Field(
        default=None,
        description="API key for authentication with LLM provider.",
    )
    api_base: str | None = Field(
        default=None,
        description="Custom base URL for the LLM API (useful for local models or proxies).",
    )
    allow_remote: bool = Field(
        default=False,
        description=(
            "Explicit authorization to send source code (and derived prompts) "
            "to endpoints that are not the local machine. Remote providers fail "
            "closed while this is false."
        ),
    )


class SandboxConfig(BaseModel):
    """Configuration settings for sandbox isolation."""

    mode: SandboxMode = Field(
        default=SandboxMode.DOCKER,
        description="Isolation backend used for running dynamic verification tests.",
    )
    timeout_seconds: int = Field(
        default=60,
        gt=0,
        description="Maximum execution timeout in seconds for single commands in the sandbox.",
    )
    memory_limit: str = Field(
        default="2g",
        min_length=1,
        description="Memory limit for the container sandbox (e.g. 512m, 2g).",
    )
    cpu_quota: float = Field(
        default=2.0,
        gt=0.0,
        description="Maximum CPU cores allocated to the sandbox container.",
    )
    image: str | None = Field(
        default=None,
        description=(
            "Container image override for the Docker backend (e.g. a locally "
            "built image with the target's runtime dependencies preinstalled)."
        ),
    )

    @field_validator("memory_limit")
    @classmethod
    def validate_memory_limit(cls, v: str) -> str:
        """Validate that memory limit string ends with an appropriate unit suffix."""
        cleaned = v.strip().lower()
        if not any(cleaned.endswith(unit) for unit in ("b", "k", "m", "g", "kb", "mb", "gb")):
            msg = f"Invalid memory limit format '{v}'. Must specify unit (e.g., '512m', '2g')."
            raise ValueError(msg)
        return v


class ScanConfig(BaseModel):
    """Configuration settings for security scan execution."""

    profile: ScanProfile = Field(
        default=ScanProfile.STANDARD,
        description="Scan depth profile controlling agent thoroughness.",
    )
    target_path: str = Field(
        default=".",
        description="Path to the target codebase or file to analyze.",
    )
    dry_run: bool = Field(
        default=False,
        description="Simulate scan execution without running dynamic tests or modifying files.",
    )
    max_turns: int = Field(
        default=10,
        gt=0,
        description="Maximum number of agent reasoning iterations permitted per task.",
    )


class OutputConfig(BaseModel):
    """Configuration settings for findings reporting and export."""

    format: OutputFormat = Field(
        default=OutputFormat.TEXT,
        description="Default format for report output.",
    )
    output_file: str | None = Field(
        default=None,
        description="Path to write the generated scan report.",
    )
    reports_dir: str | None = Field(
        default=None,
        description=(
            "Explicit directory for persisted scan reports. When unset, reports "
            "are anchored under the scanned project at '<target>/.mugiwara/reports'."
        ),
    )
    include_evidence: bool = Field(
        default=True,
        description="Whether to include full reproduction traces and logs in reports.",
    )


class AgentConfig(BaseModel):
    """Configuration settings for security agent execution and LLM budgeting.

    Defaults are intentionally conservative so an unattended scan cannot incur
    runaway token costs or read an unbounded amount of target content.
    """

    max_total_tokens: int = Field(
        default=50_000,
        gt=0,
        description=(
            "Cumulative LLM token budget (prompt + completion) for one scan session. "
            "Further LLM calls are refused once the budget is exhausted."
        ),
    )
    max_files: int = Field(
        default=200,
        gt=0,
        description="Maximum number of target source files collected per scan.",
    )
    max_file_bytes: int = Field(
        default=65_536,
        gt=0,
        description="Maximum size in bytes of a single collected source file.",
    )
    max_snippet_chars: int = Field(
        default=1_200,
        gt=0,
        description="Maximum characters of code snippet context embedded per prompt block.",
    )
    ignore_patterns: list[str] = Field(
        default_factory=list,
        description=(
            "Additional glob patterns matched against relative paths to exclude "
            "from collection (merged with the built-in ignore list)."
        ),
    )


class VerificationConfig(BaseModel):
    """Configuration settings for dynamic exploit verification (Phase 4).

    Verification is effective only when ``sandbox.mode`` is not ``none``;
    without an operational sandbox, findings remain SUSPECTED.
    """

    enabled: bool = Field(
        default=True,
        description="Whether to run dynamic PoC verification when a sandbox is available.",
    )
    max_poc_executions: int = Field(
        default=20,
        gt=0,
        description="Maximum number of PoC executions permitted per scan session.",
    )
    poc_timeout_seconds: float = Field(
        default=30.0,
        gt=0.0,
        description="Per-PoC execution timeout inside the sandbox.",
    )
    max_poc_bytes: int = Field(
        default=16_384,
        gt=0,
        description="Maximum size in bytes of a synthesized PoC script.",
    )
    readiness_wait_seconds: int = Field(
        default=10,
        ge=1,
        le=30,
        description=(
            "Seconds to wait for the target application to accept connections "
            "before running a probe."
        ),
    )


class MugiwaraSettings(BaseSettings):
    """Master configuration settings for Mugiwara Security."""

    model_config = SettingsConfigDict(
        env_prefix="MUGIWARA_",
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore",
    )

    llm: LLMConfig = Field(default_factory=LLMConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    agents: AgentConfig = Field(default_factory=AgentConfig)
    verification: VerificationConfig = Field(default_factory=VerificationConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    log_level: LogLevel = Field(
        default=LogLevel.INFO,
        description="Global logging severity level.",
    )
    config_file: str | None = Field(
        default=None,
        description="Path to the active YAML configuration file if one was loaded.",
    )


def load_settings(config_path: Path | str | None = None) -> MugiwaraSettings:
    """Load settings from optional YAML configuration file merged with environment variables.

    Args:
        config_path: Optional path to a YAML configuration file.

    Returns:
        A validated MugiwaraSettings instance.

    Raises:
        ConfigFileNotFoundError: If the specified config file does not exist.
        ConfigValidationError: If file parsing fails or values are invalid.
    """
    file_data: dict[str, Any] = {}

    if config_path is not None:
        path = Path(config_path)
        if not path.is_file():
            msg = f"Configuration file not found: {path}"
            raise ConfigFileNotFoundError(msg)

        try:
            with path.open("r", encoding="utf-8") as f:
                content = yaml.safe_load(f)
                if content is not None:
                    if not isinstance(content, dict):
                        msg = f"Config file '{path}' must contain a YAML mapping/dictionary."
                        raise ConfigValidationError(msg)
                    file_data = content
        except yaml.YAMLError as exc:
            msg = f"Failed to parse YAML configuration file '{path}': {exc}"
            raise ConfigValidationError(msg) from exc

    try:
        if config_path is not None:
            file_data["config_file"] = str(config_path)
        return MugiwaraSettings(**file_data)
    except ValidationError as exc:
        msg = f"Configuration validation failed: {exc}"
        raise ConfigValidationError(msg) from exc
