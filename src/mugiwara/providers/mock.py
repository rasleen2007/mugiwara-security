"""Deterministic mock LLM provider for zero-network unit and integration testing."""

from typing import TypeVar, cast

from pydantic import BaseModel, ValidationError

from mugiwara.core.exceptions import ProviderExecutionError
from mugiwara.providers.base import (
    BaseLLMProvider,
    CompletionRequest,
    CompletionResponse,
    TokenUsage,
)

T = TypeVar("T", bound=BaseModel)


class MockLLMProvider(BaseLLMProvider):
    """Deterministic mock provider that simulates LLM completions without network I/O.

    When no response is queued for a VerificationPlan request, a deterministic
    safety-screened plan is synthesized so demo and integration runs can
    exercise the complete dynamic verification path end to end.
    """

    def __init__(
        self,
        default_model: str = "mock-model-v1",
        default_response: str = "Mock LLM completion response.",
    ) -> None:
        self._default_model = default_model
        self.default_response = default_response
        self.mock_responses: list[str] = []
        self.mock_structured_responses: list[BaseModel] = []
        self.simulated_error: Exception | None = None
        self.call_history: list[CompletionRequest] = []
        self._plan_sequence = 0

    @property
    def provider_name(self) -> str:
        """Return provider identifier string."""
        return "mock"

    @property
    def default_model(self) -> str:
        """Return default model name."""
        return self._default_model

    def add_response(self, response: str) -> None:
        """Queue a sequential text response to be returned by future complete() calls."""
        self.mock_responses.append(response)

    def add_structured_response(self, response: BaseModel) -> None:
        """Queue a structured Pydantic model response for future generate_structured() calls."""
        self.mock_structured_responses.append(response)

    def set_error(self, error: Exception | None) -> None:
        """Configure an exception to be raised on the next completion or structured call."""
        self.simulated_error = error

    def reset(self) -> None:
        """Clear call history, response queues, simulated errors, and plan sequence."""
        self.mock_responses.clear()
        self.mock_structured_responses.clear()
        self.simulated_error = None
        self.call_history.clear()
        self._plan_sequence = 0

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        """Simulate an asynchronous text completion."""
        self.call_history.append(request)

        if self.simulated_error is not None:
            raise self.simulated_error

        content = self.mock_responses.pop(0) if self.mock_responses else self.default_response
        model_name = request.model or self.default_model

        # Estimate simple deterministic token metrics
        prompt_tokens = max(1, len(request.prompt.split()))
        completion_tokens = max(1, len(content.split()))
        usage = TokenUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
        )

        return CompletionResponse(
            content=content,
            model=model_name,
            provider=self.provider_name,
            usage=usage,
            raw_response={"mock": True, "model": model_name},
        )

    async def generate_structured(
        self,
        schema: type[T],
        request: CompletionRequest,
    ) -> T:
        """Simulate structured Pydantic response generation."""
        self.call_history.append(request)

        if self.simulated_error is not None:
            raise self.simulated_error

        # If a structured response is explicitly queued, pop and validate it
        if self.mock_structured_responses:
            queued = self.mock_structured_responses.pop(0)
            if isinstance(queued, schema):
                return queued
            # If queued response is another model, try to cast/validate
            try:
                return schema.model_validate(queued.model_dump())
            except ValidationError as exc:
                msg = f"Queued mock response {type(queued)} does not match schema {schema}."
                raise ProviderExecutionError(msg) from exc

        # If a string response is queued, try parsing it as JSON into the schema
        if self.mock_responses:
            raw_json = self.mock_responses.pop(0)
            try:
                return schema.model_validate_json(raw_json)
            except ValidationError as exc:
                msg = f"Failed to validate mock JSON string into schema {schema}: {exc}"
                raise ProviderExecutionError(msg) from exc

        # If nothing is queued, synthesize deterministic responses so demo runs
        # exercise the full Phase 4/6 paths without network access. Imported
        # lazily to avoid a circular import with the agents package.
        from mugiwara.agents.models import RemediationPlan, VerificationPlan
        from mugiwara.providers.mock_remediation import build_default_remediation_plan
        from mugiwara.providers.mock_verification import build_default_verification_plan

        if schema is VerificationPlan:
            plan = build_default_verification_plan(request.prompt, self._plan_sequence)
            self._plan_sequence += 1
            return cast(T, plan)

        if schema is RemediationPlan:
            return cast(T, build_default_remediation_plan(request.prompt))

        # As a last resort, attempt instantiating default schema if it has all defaults
        try:
            return schema()
        except ValidationError as exc:
            msg = (
                f"Cannot generate default structured response for schema '{schema.__name__}'. "
                f"Use provider.add_structured_response() to queue a valid instance for testing."
            )
            raise ProviderExecutionError(msg) from exc

    async def health_check(self) -> bool:
        """Simulate provider health check."""
        return self.simulated_error is None
