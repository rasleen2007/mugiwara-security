"""Unit tests for LLM provider abstraction and Mock provider."""

import asyncio

import pytest
from pydantic import BaseModel, Field

from mugiwara.core.config import LLMConfig, LLMProviderType
from mugiwara.core.exceptions import (
    ProviderError,
    ProviderExecutionError,
    ProviderNotSupportedError,
)
from mugiwara.providers import (
    ChatMessage,
    CompletionRequest,
    CompletionResponse,
    MockLLMProvider,
    TokenUsage,
    get_provider,
)


class SampleStructuredOutput(BaseModel):
    """Sample schema for testing structured generation."""

    vulnerability_type: str = "sql_injection"
    confidence: float = 0.95
    is_exploitable: bool = True


class StrictSchema(BaseModel):
    """Schema with required fields without defaults."""

    target_endpoint: str = Field(min_length=1)
    risk_level: str = Field(min_length=1)


@pytest.mark.asyncio
async def test_mock_provider_default_completion() -> None:
    """Verify default mock completion response and metadata."""
    provider = MockLLMProvider()
    request = CompletionRequest(prompt="Find SQL injection vulnerabilities in this code.")

    response = await provider.complete(request)

    assert isinstance(response, CompletionResponse)
    assert response.content == "Mock LLM completion response."
    assert response.model == "mock-model-v1"
    assert response.provider == "mock"
    assert response.usage.prompt_tokens > 0
    assert response.usage.completion_tokens > 0
    assert len(provider.call_history) == 1
    assert provider.call_history[0].prompt == request.prompt


@pytest.mark.asyncio
async def test_mock_provider_model_override() -> None:
    """Verify overriding model in completion request."""
    provider = MockLLMProvider(default_model="default-mock")
    request = CompletionRequest(prompt="Test prompt", model="custom-mock-v2")

    response = await provider.complete(request)

    assert response.model == "custom-mock-v2"


@pytest.mark.asyncio
async def test_mock_provider_queued_sequential_responses() -> None:
    """Verify FIFO queueing of sequential mock text responses."""
    provider = MockLLMProvider()
    provider.add_response("First response: scanning auth.")
    provider.add_response("Second response: found potential IDOR.")

    r1 = await provider.complete(CompletionRequest(prompt="Step 1"))
    r2 = await provider.complete(CompletionRequest(prompt="Step 2"))
    r3 = await provider.complete(CompletionRequest(prompt="Step 3"))  # Falls back to default

    assert r1.content == "First response: scanning auth."
    assert r2.content == "Second response: found potential IDOR."
    assert r3.content == provider.default_response
    assert len(provider.call_history) == 3


@pytest.mark.asyncio
async def test_mock_provider_concurrent_async_completions() -> None:
    """Verify asynchronous concurrency with asyncio.gather."""
    provider = MockLLMProvider()
    requests = [CompletionRequest(prompt=f"Task {i}") for i in range(5)]

    responses = await asyncio.gather(*(provider.complete(req) for req in requests))

    assert len(responses) == 5
    assert len(provider.call_history) == 5
    for resp in responses:
        assert resp.content == provider.default_response


@pytest.mark.asyncio
async def test_mock_provider_structured_output_default() -> None:
    """Verify generating structured Pydantic response with default schema values."""
    provider = MockLLMProvider()
    request = CompletionRequest(prompt="Analyze risk")

    result = await provider.generate_structured(SampleStructuredOutput, request)

    assert isinstance(result, SampleStructuredOutput)
    assert result.vulnerability_type == "sql_injection"
    assert result.confidence == 0.95
    assert result.is_exploitable is True


@pytest.mark.asyncio
async def test_mock_provider_queued_structured_response() -> None:
    """Verify returning explicitly queued structured Pydantic instances."""
    provider = MockLLMProvider()
    expected = StrictSchema(target_endpoint="/api/v1/user", risk_level="CRITICAL")
    provider.add_structured_response(expected)

    result = await provider.generate_structured(
        StrictSchema, CompletionRequest(prompt="Target scan")
    )

    assert isinstance(result, StrictSchema)
    assert result.target_endpoint == "/api/v1/user"
    assert result.risk_level == "CRITICAL"


@pytest.mark.asyncio
async def test_mock_provider_queued_json_string_structured_response() -> None:
    """Verify parsing queued mock JSON string into target structured schema."""
    provider = MockLLMProvider()
    json_payload = '{"target_endpoint": "/auth/token", "risk_level": "HIGH"}'
    provider.add_response(json_payload)

    result = await provider.generate_structured(
        StrictSchema, CompletionRequest(prompt="Scan auth endpoint")
    )

    assert isinstance(result, StrictSchema)
    assert result.target_endpoint == "/auth/token"
    assert result.risk_level == "HIGH"


@pytest.mark.asyncio
async def test_mock_provider_strict_schema_failure_when_not_queued() -> None:
    """Verify ProviderExecutionError when a strict schema cannot be auto-instantiated."""
    provider = MockLLMProvider()
    with pytest.raises(ProviderExecutionError, match="Cannot generate default structured response"):
        await provider.generate_structured(StrictSchema, CompletionRequest(prompt="Scan"))


@pytest.mark.asyncio
async def test_mock_provider_simulated_error() -> None:
    """Verify simulating provider exceptions on completion and structured generation."""
    provider = MockLLMProvider()
    simulated_exc = ProviderError("Simulated LLM rate limit or connection timeout.")
    provider.set_error(simulated_exc)

    with pytest.raises(ProviderError, match="Simulated LLM rate limit"):
        await provider.complete(CompletionRequest(prompt="test"))

    with pytest.raises(ProviderError, match="Simulated LLM rate limit"):
        await provider.generate_structured(SampleStructuredOutput, CompletionRequest(prompt="test"))

    # Health check should return False when error is configured
    assert await provider.health_check() is False

    # Clear error
    provider.set_error(None)
    assert await provider.health_check() is True


def test_mock_provider_reset() -> None:
    """Verify resetting mock provider state."""
    provider = MockLLMProvider()
    provider.add_response("queued")
    provider.set_error(RuntimeError("error"))

    provider.reset()

    assert len(provider.mock_responses) == 0
    assert len(provider.mock_structured_responses) == 0
    assert provider.simulated_error is None
    assert len(provider.call_history) == 0


def test_factory_returns_mock_provider() -> None:
    """Verify factory initializes MockLLMProvider for mock provider type."""
    cfg = LLMConfig(provider=LLMProviderType.MOCK, model="test-mock-model")
    provider = get_provider(cfg)

    assert isinstance(provider, MockLLMProvider)
    assert provider.provider_name == "mock"
    assert provider.default_model == "test-mock-model"


@pytest.mark.parametrize(
    "provider_type",
    [
        LLMProviderType.OPENAI,
        LLMProviderType.ANTHROPIC,
        LLMProviderType.GEMINI,
        LLMProviderType.OLLAMA,
    ],
)
def test_factory_rejects_deferred_real_providers(provider_type: LLMProviderType) -> None:
    """Verify factory raises ProviderNotSupportedError mentioning deferred future phase."""
    cfg = LLMConfig(provider=provider_type)
    with pytest.raises(ProviderNotSupportedError) as exc_info:
        get_provider(cfg)

    assert "deferred to a future phase" in str(exc_info.value)
    assert provider_type.value in str(exc_info.value)


def test_provider_dto_models() -> None:
    """Verify creation and serialization of ChatMessage, TokenUsage, and CompletionRequest."""
    msg = ChatMessage(role="user", content="Test question")
    req = CompletionRequest(
        prompt="Execute test",
        system_prompt="You are a security auditor.",
        messages=[msg],
        temperature=0.2,
        max_tokens=1000,
    )
    assert req.system_prompt == "You are a security auditor."
    assert len(req.messages) == 1

    usage = TokenUsage(prompt_tokens=10, completion_tokens=20, total_tokens=30)
    assert usage.total_tokens == 30
