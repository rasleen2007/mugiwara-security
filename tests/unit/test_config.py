"""Unit tests for Mugiwara Security configuration system."""

from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from mugiwara.core.config import (
    LLMConfig,
    LLMProviderType,
    LogLevel,
    MugiwaraSettings,
    OutputConfig,
    OutputFormat,
    SandboxConfig,
    SandboxMode,
    ScanConfig,
    ScanProfile,
    load_settings,
)
from mugiwara.core.exceptions import (
    ConfigFileNotFoundError,
    ConfigValidationError,
)


def test_default_settings() -> None:
    """Verify default configuration values across all subsystems."""
    settings = load_settings()

    # LLM defaults - local-first: no cloud API key needed on a fresh install
    assert settings.llm.provider == LLMProviderType.OLLAMA
    assert settings.llm.model == "llama3.2"
    assert settings.llm.temperature == 0.0
    assert settings.llm.max_tokens == 4096
    assert settings.llm.timeout_seconds == 60.0
    assert settings.llm.api_key is None
    assert settings.llm.api_base is None
    assert settings.llm.allow_remote is False

    # Sandbox defaults
    assert settings.sandbox.mode == SandboxMode.DOCKER
    assert settings.sandbox.timeout_seconds == 60
    assert settings.sandbox.memory_limit == "2g"
    assert settings.sandbox.cpu_quota == 2.0

    # Scan defaults
    assert settings.scan.profile == ScanProfile.STANDARD
    assert settings.scan.target_path == "."
    assert settings.scan.dry_run is False
    assert settings.scan.max_turns == 10

    # Output defaults
    assert settings.output.format == OutputFormat.TEXT
    assert settings.output.output_file is None
    assert settings.output.include_evidence is True

    # Global log level
    assert settings.log_level == LogLevel.INFO
    assert settings.config_file is None


def test_secret_str_masking() -> None:
    """Verify that sensitive API keys are masked and never leaked in representations."""
    raw_key = "sk-super-secret-production-key-12345"
    llm_cfg = LLMConfig(api_key=SecretStr(raw_key))

    # Plain str and repr must mask the secret
    assert raw_key not in str(llm_cfg)
    assert raw_key not in repr(llm_cfg)
    assert "**********" in repr(llm_cfg)

    # Secret is only retrievable via explicit accessor
    assert llm_cfg.api_key is not None
    assert llm_cfg.api_key.get_secret_value() == raw_key


def test_environment_variable_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that environment variables with MUGIWARA_ prefix override defaults."""
    monkeypatch.setenv("MUGIWARA_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("MUGIWARA_LLM__PROVIDER", "anthropic")
    monkeypatch.setenv("MUGIWARA_LLM__MODEL", "claude-3-5-sonnet-20241022")
    monkeypatch.setenv("MUGIWARA_LLM__TEMPERATURE", "0.7")
    monkeypatch.setenv("MUGIWARA_LLM__API_KEY", "sk-ant-test-999")
    monkeypatch.setenv("MUGIWARA_SANDBOX__MODE", "none")
    monkeypatch.setenv("MUGIWARA_SANDBOX__TIMEOUT_SECONDS", "120")
    monkeypatch.setenv("MUGIWARA_SCAN__PROFILE", "deep")
    monkeypatch.setenv("MUGIWARA_SCAN__DRY_RUN", "true")
    monkeypatch.setenv("MUGIWARA_OUTPUT__FORMAT", "sarif")

    settings = load_settings()

    assert settings.log_level == LogLevel.DEBUG
    assert settings.llm.provider == LLMProviderType.ANTHROPIC
    assert settings.llm.model == "claude-3-5-sonnet-20241022"
    assert settings.llm.temperature == 0.7
    assert settings.llm.api_key is not None
    assert settings.llm.api_key.get_secret_value() == "sk-ant-test-999"
    assert settings.sandbox.mode == SandboxMode.NONE
    assert settings.sandbox.timeout_seconds == 120
    assert settings.scan.profile == ScanProfile.DEEP
    assert settings.scan.dry_run is True
    assert settings.output.format == OutputFormat.SARIF


def test_load_yaml_config_file(tmp_path: Path) -> None:
    """Verify loading and parsing configuration from a valid YAML file."""
    config_file = tmp_path / "mugiwara.yaml"
    config_content = """
log_level: WARNING
llm:
  provider: gemini
  model: gemini-1.5-pro
  temperature: 0.2
sandbox:
  mode: docker
  memory_limit: 4g
  cpu_quota: 4.0
scan:
  profile: fast
  max_turns: 5
output:
  format: json
  output_file: scan_results.json
"""
    config_file.write_text(config_content, encoding="utf-8")

    settings = load_settings(config_path=config_file)

    assert settings.log_level == LogLevel.WARNING
    assert settings.llm.provider == LLMProviderType.GEMINI
    assert settings.llm.model == "gemini-1.5-pro"
    assert settings.llm.temperature == 0.2
    assert settings.sandbox.memory_limit == "4g"
    assert settings.sandbox.cpu_quota == 4.0
    assert settings.scan.profile == ScanProfile.FAST
    assert settings.scan.max_turns == 5
    assert settings.output.format == OutputFormat.JSON
    assert settings.output.output_file == "scan_results.json"
    assert settings.config_file == str(config_file)


def test_missing_config_file_raises_error() -> None:
    """Verify that requesting a non-existent configuration file raises ConfigFileNotFoundError."""
    non_existent = Path("non_existent_mugiwara_config.yaml")
    with pytest.raises(ConfigFileNotFoundError, match="Configuration file not found"):
        load_settings(config_path=non_existent)


def test_invalid_yaml_syntax_raises_error(tmp_path: Path) -> None:
    """Verify that malformed YAML syntax raises ConfigValidationError."""
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("llm: [unclosed list", encoding="utf-8")

    with pytest.raises(ConfigValidationError, match="Failed to parse YAML"):
        load_settings(config_path=bad_yaml)


def test_non_dict_yaml_content_raises_error(tmp_path: Path) -> None:
    """Verify that YAML containing a non-dictionary root raises ConfigValidationError."""
    list_yaml = tmp_path / "list.yaml"
    list_yaml.write_text("- item 1\n- item 2\n", encoding="utf-8")

    with pytest.raises(ConfigValidationError, match="must contain a YAML mapping/dictionary"):
        load_settings(config_path=list_yaml)


def test_invalid_temperature_validation() -> None:
    """Verify that temperatures outside [0.0, 2.0] trigger validation errors."""
    with pytest.raises(ConfigValidationError):
        load_settings_from_dict({"llm": {"temperature": 2.5}})

    with pytest.raises(ConfigValidationError):
        load_settings_from_dict({"llm": {"temperature": -0.1}})


def test_invalid_memory_limit_format() -> None:
    """Verify that memory limits without unit suffixes trigger validation errors."""
    with pytest.raises(ConfigValidationError, match="Invalid memory limit format"):
        load_settings_from_dict({"sandbox": {"memory_limit": "2048"}})


def test_invalid_enum_values() -> None:
    """Verify that invalid enum values raise ConfigValidationError."""
    with pytest.raises(ConfigValidationError):
        load_settings_from_dict({"llm": {"provider": "unsupported_provider"}})

    with pytest.raises(ConfigValidationError):
        load_settings_from_dict({"scan": {"profile": "ultra_mega_deep"}})


def test_custom_instantiation() -> None:
    """Verify programmatic direct instantiation of MugiwaraSettings with custom sub-configs."""
    custom = MugiwaraSettings(
        llm=LLMConfig(provider=LLMProviderType.OLLAMA, model="deepseek-r1:14b"),
        sandbox=SandboxConfig(mode=SandboxMode.NONE),
        scan=ScanConfig(profile=ScanProfile.DEEP, target_path="/app"),
        output=OutputConfig(format=OutputFormat.MARKDOWN, output_file="report.md"),
    )
    assert custom.llm.provider == LLMProviderType.OLLAMA
    assert custom.llm.model == "deepseek-r1:14b"
    assert custom.sandbox.mode == SandboxMode.NONE
    assert custom.scan.target_path == "/app"
    assert custom.output.format == OutputFormat.MARKDOWN


def load_settings_from_dict(data: dict[str, Any]) -> MugiwaraSettings:
    """Helper to simulate loading settings from a dictionary for validation tests."""
    try:
        return MugiwaraSettings.model_validate(data)
    except Exception as exc:
        raise ConfigValidationError(str(exc)) from exc
