"""Unit tests for the local Ollama provider (fake transport, zero network)."""

import asyncio
import os
from typing import Any

import pytest
from pydantic import BaseModel, Field

from mugiwara.core.config import LLMConfig, LLMProviderType
from mugiwara.core.exceptions import ProviderExecutionError, ProviderNotSupportedError
from mugiwara.providers import (
    CompletionRequest,
    OllamaProvider,
    get_provider,
)
from mugiwara.providers.ollama import (
    DEFAULT_OLLAMA_BASE_URL,
    extract_json_object,
)
from mugiwara.providers.transport import TransportError, UrllibTransport, validate_pinned_url


class SampleOutput(BaseModel):
    """Sample schema mirroring agent structured outputs."""

    finding_type: str = Field(min_length=1)
    confidence: float


def _config(**overrides: Any) -> LLMConfig:
    values: dict[str, Any] = {
        "provider": LLMProviderType.OLLAMA,
        "model": "llama3.1:8b",
        "timeout_seconds": 7.5,
        "temperature": 0.0,
        "max_tokens": 512,
    }
    values.update(overrides)
    return LLMConfig(**values)


class FakeTransport:
    """Scriptable in-memory transport satisfying the Transport protocol."""

    def __init__(self) -> None:
        self.post_calls: list[tuple[str, dict[str, Any], float]] = []
        self.get_calls: list[tuple[str, float]] = []
        self.post_responses: list[dict[str, Any] | Exception] = []
        self.get_responses: list[dict[str, Any] | Exception] = []

    def queue_post(self, response: dict[str, Any] | Exception) -> None:
        self.post_responses.append(response)

    def post_json(
        self, url: str, payload: dict[str, Any], timeout_seconds: float
    ) -> dict[str, Any]:
        self.post_calls.append((url, payload, timeout_seconds))
        outcome = (
            self.post_responses.pop(0)
            if self.post_responses
            else {"message": {"content": "{}"}, "model": payload["model"]}
        )
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def get_json(self, url: str, timeout_seconds: float) -> dict[str, Any]:
        self.get_calls.append((url, timeout_seconds))
        outcome = self.get_responses.pop(0) if self.get_responses else {"models": []}
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _ollama_response(content: str, prompt_eval: int = 11, eval_count: int = 22) -> dict[str, Any]:
    return {
        "model": "llama3.1:8b",
        "message": {"role": "assistant", "content": content},
        "prompt_eval_count": prompt_eval,
        "eval_count": eval_count,
        "done": True,
    }


# -- complete() ---------------------------------------------------------------


def test_complete_posts_chat_payload_to_local_endpoint() -> None:
    transport = FakeTransport()
    transport.queue_post(_ollama_response("hello"))
    provider = OllamaProvider(_config(), transport=transport)

    response = asyncio.run(provider.complete(CompletionRequest(prompt="analyze this")))

    assert response.content == "hello"
    assert response.provider == "ollama"
    assert response.model == "llama3.1:8b"
    url, payload, timeout = transport.post_calls[0]
    assert url == f"{DEFAULT_OLLAMA_BASE_URL}/api/chat"
    assert timeout == 7.5
    assert payload["stream"] is False
    assert "format" not in payload
    assert payload["options"]["temperature"] == 0.0
    assert payload["options"]["num_predict"] == 512
    assert payload["messages"] == [{"role": "user", "content": "analyze this"}]


def test_complete_maps_real_usage_counters_for_budget_accounting() -> None:
    transport = FakeTransport()
    transport.queue_post(_ollama_response("answer", prompt_eval=100, eval_count=30))
    provider = OllamaProvider(_config(), transport=transport)

    response = asyncio.run(provider.complete(CompletionRequest(prompt="p")))

    assert response.usage.prompt_tokens == 100
    assert response.usage.completion_tokens == 30
    assert response.usage.total_tokens == 130


def test_complete_tolerates_missing_usage_fields() -> None:
    transport = FakeTransport()
    transport.queue_post({"message": {"content": "x"}, "model": "m"})
    provider = OllamaProvider(_config(), transport=transport)

    response = asyncio.run(provider.complete(CompletionRequest(prompt="p")))

    assert response.usage.total_tokens == 0


def test_complete_includes_system_prompt_and_multi_turn_messages() -> None:
    from mugiwara.providers.base import ChatMessage

    transport = FakeTransport()
    provider = OllamaProvider(_config(), transport=transport)
    request = CompletionRequest(
        system_prompt="You are a security analyst.",
        messages=[
            ChatMessage(role="user", content="first"),
            ChatMessage(role="assistant", content="reply"),
            ChatMessage(role="user", content="next"),
        ],
    )

    asyncio.run(provider.complete(request))

    _, payload, _ = transport.post_calls[0]
    roles = [m["role"] for m in payload["messages"]]
    contents = [m["content"] for m in payload["messages"]]
    assert roles == ["system", "user", "assistant", "user"]
    assert contents[0] == "You are a security analyst."
    assert contents[-1] == "next"


# -- generate_structured() -----------------------------------------------------


def test_generate_structured_validates_plain_json_response() -> None:
    transport = FakeTransport()
    transport.queue_post(_ollama_response('{"finding_type": "sqli", "confidence": 0.9}'))
    provider = OllamaProvider(_config(), transport=transport)

    result = asyncio.run(
        provider.generate_structured(SampleOutput, CompletionRequest(prompt="find issues"))
    )

    assert result.finding_type == "sqli"
    assert result.confidence == pytest.approx(0.9)
    _, payload, _ = transport.post_calls[0]
    assert payload["format"] == "json"
    system_content = payload["messages"][0]["content"]
    assert "JSON object" in system_content
    assert '"finding_type"' in system_content


def test_generate_structured_extracts_fenced_json() -> None:
    fenced = '```json\n{"finding_type": "xss", "confidence": 0.5}\n```'
    transport = FakeTransport()
    transport.queue_post(_ollama_response(fenced))
    provider = OllamaProvider(_config(), transport=transport)

    result = asyncio.run(provider.generate_structured(SampleOutput, CompletionRequest(prompt="p")))

    assert result.finding_type == "xss"


def test_generate_structured_extracts_embedded_json_from_prose() -> None:
    noisy = (
        "Here is my analysis:\n"
        'Some preamble {"finding_type": "rce", "confidence": 0.8} hope that helps!'
    )
    transport = FakeTransport()
    transport.queue_post(_ollama_response(noisy))
    provider = OllamaProvider(_config(), transport=transport)

    result = asyncio.run(provider.generate_structured(SampleOutput, CompletionRequest(prompt="p")))

    assert result.finding_type == "rce"


def test_generate_structured_rejects_schema_violations() -> None:
    transport = FakeTransport()
    transport.queue_post(_ollama_response('{"confidence": "not-a-number"}'))
    provider = OllamaProvider(_config(), transport=transport)

    with pytest.raises(ProviderExecutionError, match="schema validation"):
        asyncio.run(provider.generate_structured(SampleOutput, CompletionRequest(prompt="p")))


def test_generate_structured_fails_cleanly_without_any_json() -> None:
    transport = FakeTransport()
    transport.queue_post(_ollama_response("I cannot answer that."))
    provider = OllamaProvider(_config(), transport=transport)

    with pytest.raises(ProviderExecutionError, match="JSON object"):
        asyncio.run(provider.generate_structured(SampleOutput, CompletionRequest(prompt="p")))


# -- error handling ------------------------------------------------------------


def test_transport_failures_surface_as_provider_execution_errors() -> None:
    transport = FakeTransport()
    transport.queue_post(TransportError("connection refused"))
    provider = OllamaProvider(_config(), transport=transport)

    with pytest.raises(ProviderExecutionError, match="connection refused"):
        asyncio.run(provider.complete(CompletionRequest(prompt="p")))


def test_health_check_reflects_daemon_availability() -> None:
    healthy = FakeTransport()
    provider_ok = OllamaProvider(_config(), transport=healthy)
    assert asyncio.run(provider_ok.health_check()) is True

    dead = FakeTransport()
    dead.get_responses.append(TransportError("connection refused"))
    provider_dead = OllamaProvider(_config(), transport=dead)
    assert asyncio.run(provider_dead.health_check()) is False


# -- endpoint pinning (no socket may be opened in these tests) ------------------


def test_pinned_url_validation_accepts_configured_origin() -> None:
    validate_pinned_url("http://127.0.0.1:11434", "http://127.0.0.1:11434/api/chat")
    validate_pinned_url("http://127.0.0.1:11434/", "http://127.0.0.1:11434/api/tags")


@pytest.mark.parametrize(
    ("base_url", "url"),
    [
        ("http://127.0.0.1:11434", "http://169.254.169.254/latest/meta-data"),
        ("http://127.0.0.1:11434", "http://127.0.0.1:11434.evil.test/api/chat"),
        ("http://127.0.0.1:11434", "https://other-host.test/api/chat"),
        ("http://127.0.0.1:11434", "file:///etc/passwd"),
        ("http://127.0.0.1:11434", "ftp://127.0.0.1:11434/api/chat"),
    ],
)
def test_pinned_url_validation_refuses_foreign_destinations(
    base_url: str,
    url: str,
) -> None:
    with pytest.raises(TransportError):
        validate_pinned_url(base_url, url)


def test_urllib_transport_never_opens_socket_for_disallowed_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def exploding_urlopen(*args: Any, **kwargs: Any) -> None:
        msg = "socket must never be opened for pinned-URL violations"
        raise AssertionError(msg)

    monkeypatch.setattr("urllib.request.urlopen", exploding_urlopen)
    transport = UrllibTransport("http://127.0.0.1:11434")

    with pytest.raises(TransportError, match="outside the configured endpoint"):
        transport.post_json("http://evil.test/api/chat", {}, 1.0)


def test_custom_api_base_is_respected_and_pinned() -> None:
    config = _config(api_base="http://localhost:9998/ollama/")
    transport = FakeTransport()
    provider = OllamaProvider(config, transport=transport)

    asyncio.run(provider.complete(CompletionRequest(prompt="p")))

    url, _, _ = transport.post_calls[0]
    assert url == "http://localhost:9998/ollama/api/chat"


# -- factory wiring ------------------------------------------------------------


def test_factory_returns_ollama_provider_for_local_config() -> None:
    provider = get_provider(_config())

    assert isinstance(provider, OllamaProvider)
    assert provider.provider_name == "ollama"
    assert provider.default_model == "llama3.1:8b"


def test_factory_still_defers_remote_providers() -> None:
    for remote in (LLMProviderType.OPENAI, LLMProviderType.ANTHROPIC, LLMProviderType.GEMINI):
        with pytest.raises(ProviderNotSupportedError):
            get_provider(_config(provider=remote))


# -- JSON extraction unit coverage ----------------------------------------------


def test_extract_json_object_variants() -> None:
    assert extract_json_object('{"a": 1}') == {"a": 1}
    assert extract_json_object('noise {"a": {"b": 2}} tail') == {"a": {"b": 2}}
    assert extract_json_object('```\n{"a": 3}\n```') == {"a": 3}
    with pytest.raises(ProviderExecutionError):
        extract_json_object("[1, 2, 3]")


# -- opt-in live integration test ----------------------------------------------

_LIVE_ENV_VAR = "MUGIWARA_OLLAMA_INTEGRATION"
_LIVE_MODEL_ENV_VAR = "MUGIWARA_OLLAMA_MODEL"


@pytest.mark.skipif(
    os.environ.get(_LIVE_ENV_VAR) != "1",
    reason=f"set {_LIVE_ENV_VAR}=1 with a local Ollama daemon to run",
)
def test_live_local_ollama_round_trip() -> None:
    model = os.environ.get(_LIVE_MODEL_ENV_VAR, "llama3.1:8b")
    provider = OllamaProvider(_config(model=model))

    assert asyncio.run(provider.health_check()) is True
    response = asyncio.run(provider.complete(CompletionRequest(prompt="Reply with OK.")))
    assert response.content.strip()
    structured = asyncio.run(
        provider.generate_structured(
            SampleOutput,
            CompletionRequest(
                prompt=(
                    'Report a single finding as JSON with keys "finding_type"'
                    ' (value "sql_injection") and "confidence" (number between 0 and 1).'
                )
            ),
        )
    )
    assert structured.finding_type
