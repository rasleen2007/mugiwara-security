"""Unit tests for provider/config wiring, egress consent, and secret screening.

No real network I/O: Ollama interactions use the in-memory FakeTransport.
"""

import asyncio
from pathlib import Path
from typing import Any

import pytest
import yaml

from mugiwara.cli.commands.init import TEMPLATE_CONFIG
from mugiwara.core.config import LLMConfig, LLMProviderType, load_settings
from mugiwara.core.exceptions import (
    ProviderNotSupportedError,
    RemoteProviderNotAuthorizedError,
)
from mugiwara.providers import CompletionRequest, OllamaProvider, get_provider
from mugiwara.providers.egress import (
    ensure_provider_egress_allowed,
    is_local_http_url,
    redact_source_secrets,
)


def _config(**overrides: Any) -> LLMConfig:
    values: dict[str, Any] = {"provider": LLMProviderType.OLLAMA}
    values.update(overrides)
    return LLMConfig(**values)


class FakeTransport:
    """Scriptable in-memory transport satisfying the Transport protocol."""

    def __init__(self) -> None:
        self.post_calls: list[tuple[str, dict[str, Any], float]] = []

    def post_json(
        self, url: str, payload: dict[str, Any], timeout_seconds: float
    ) -> dict[str, Any]:
        self.post_calls.append((url, payload, timeout_seconds))
        return {"message": {"content": "{}"}, "model": payload["model"]}

    def get_json(self, url: str, timeout_seconds: float) -> dict[str, Any]:
        return {"models": []}


# -- fresh-install posture ------------------------------------------------------


def test_fresh_install_defaults_are_local_first() -> None:
    settings = load_settings()

    assert settings.llm.provider is LLMProviderType.OLLAMA
    assert settings.llm.api_key is None
    assert settings.llm.allow_remote is False


def test_init_template_is_valid_config_and_local_only() -> None:
    parsed = yaml.safe_load(TEMPLATE_CONFIG)

    assert parsed["llm"]["provider"] == "ollama"
    assert parsed["llm"]["allow_remote"] is False

    config = LLMConfig(**parsed["llm"])
    assert config.provider is LLMProviderType.OLLAMA
    assert config.allow_remote is False


def test_init_template_written_to_disk_loads_cleanly(tmp_path: Path) -> None:
    target = tmp_path / "mugiwara.yaml"
    target.write_text(TEMPLATE_CONFIG, encoding="utf-8")

    settings = load_settings(config_path=str(target))

    assert settings.llm.provider is LLMProviderType.OLLAMA
    assert settings.llm.allow_remote is False


# -- locality policy --------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:11434/api/chat",
        "http://localhost:11434",
        "http://LOCALHOST:8080/x",
        "http://[::1]:11434/api/tags",
        "https://127.0.0.1:5000",
    ],
)
def test_local_urls_recognized(url: str) -> None:
    assert is_local_http_url(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "http://192.168.1.10:11434",
        "https://api.openai.com/v1",
        "file:///etc/passwd",
        "ftp://127.0.0.1:21",
        "",
    ],
)
def test_nonlocal_urls_recognized(url: str) -> None:
    assert is_local_http_url(url) is False


def test_egress_gate_allows_loopback_without_consent() -> None:
    base = ensure_provider_egress_allowed(_config(), "http://127.0.0.1:11434")
    assert base == "http://127.0.0.1:11434"


def test_egress_gate_blocks_lan_endpoint_without_consent() -> None:
    with pytest.raises(RemoteProviderNotAuthorizedError, match="allow_remote"):
        ensure_provider_egress_allowed(
            _config(api_base="http://10.1.2.3:11434"), "http://10.1.2.3:11434"
        )


def test_egress_gate_permits_remote_only_with_explicit_consent() -> None:
    config = _config(api_base="http://gpu-box.lan:11434", allow_remote=True)
    base = ensure_provider_egress_allowed(config, "http://gpu-box.lan:11434")
    assert base == "http://gpu-box.lan:11434"


# -- provider construction enforcement ---------------------------------------------


def test_factory_rejects_nonlocal_ollama_without_consent() -> None:
    config = _config(api_base="http://10.9.9.9:11434")

    with pytest.raises(RemoteProviderNotAuthorizedError):
        get_provider(config)


def test_direct_ollama_construction_enforces_same_gate() -> None:
    with pytest.raises(RemoteProviderNotAuthorizedError):
        OllamaProvider(_config(api_base="https://ollama.corp.example"))


def test_consented_nonlocal_ollama_constructs_and_pins_transport(
    tmp_path: Path,
) -> None:
    config = _config(api_base="http://gpu-box.lan:11434", allow_remote=True)
    provider = OllamaProvider(config, transport=FakeTransport())

    asyncio.run(provider.health_check())
    assert provider.default_model == config.model


# -- secret screening on the consented remote path ---------------------------------


def test_redaction_covers_common_secret_shapes() -> None:
    sample = "\n".join(
        [
            "aws_id = AKIAIOSFODNN7EXAMPLE",
            "gh = ghp_16CharactersXXXXXXXXXXXXXXXXX",
            "slack = xoxb-123456789012-abcdef",
            "authorization: Bearer abc.def.ghi-jkl",
            'API_KEY: "super-secret-value-123"',
            "password = 'hunter2!'",
            "db_token = deadbeefcafebabe0123456789abcdef",
        ]
    )

    redacted = redact_source_secrets(sample)

    for secret in (
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_16CharactersXXXXXXXXXXXXXXXXX",
        "xoxb-123456789012-abcdef",
        "abc.def.ghi-jkl",
        "super-secret-value-123",
        "hunter2!",
        "deadbeefcafebabe0123456789abcdef",
    ):
        assert secret not in redacted, secret
    assert "[REDACTED]" in redacted


def test_redaction_preserves_private_key_block_shape() -> None:
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    assert "MIIEowIBAAKCAQEA" not in redact_source_secrets(pem)
    assert "[REDACTED]" in redact_source_secrets(pem)


def test_redaction_leaves_benign_code_alone() -> None:
    benign = (
        "def rotate_api_key(user):  # function names are fine\n"
        "    return hashlib.sha256(user.encode()).hexdigest()\n"
    )
    assert redact_source_secrets(benign) == benign


def test_remote_path_redacts_prompts_before_send() -> None:
    config = _config(api_base="http://gpu-box.lan:11434", allow_remote=True)
    transport = FakeTransport()
    provider = OllamaProvider(config, transport=transport)

    request = CompletionRequest(prompt='Use this code: api_key = "sk-live-abcdef123456"')
    asyncio.run(provider.complete(request))

    _, payload, _ = transport.post_calls[0]
    sent = json_dumps_messages(payload)
    assert "sk-live-abcdef123456" not in sent
    assert "[REDACTED]" in sent


def test_local_path_keeps_prompts_unredacted() -> None:
    transport = FakeTransport()
    provider = OllamaProvider(_config(), transport=transport)

    request = CompletionRequest(prompt='Check api_key = "sk-local-xyz987654"')
    asyncio.run(provider.complete(request))

    _, payload, _ = transport.post_calls[0]
    sent = json_dumps_messages(payload)
    assert "sk-local-xyz987654" in sent


def json_dumps_messages(payload: dict[str, Any]) -> str:
    """Helper flattening message contents into one searchable string."""
    import json

    return json.dumps(payload["messages"])


# -- factory fail-closed matrix ------------------------------------------------------


@pytest.mark.parametrize("remote", list(LLMProviderType)[:3])
def test_remote_cloud_providers_fail_closed_even_with_consent(
    remote: LLMProviderType,
) -> None:
    with pytest.raises(ProviderNotSupportedError):
        get_provider(_config(provider=remote, allow_remote=True))
