"""Base protocol and data models for LLM provider abstractions."""

from abc import ABC, abstractmethod
from typing import Any, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T", bound=BaseModel)


class ChatMessage(BaseModel):
    """Represents a single message in a chat-based LLM conversation."""

    role: str = Field(
        description="Role of the message author (e.g. 'system', 'user', 'assistant').",
    )
    content: str = Field(
        description="Text content of the message.",
    )


class CompletionRequest(BaseModel):
    """Parameters for an LLM text or structured completion request."""

    prompt: str = Field(
        default="",
        description="Main prompt text for single-turn completions.",
    )
    system_prompt: str | None = Field(
        default=None,
        description="System prompt defining agent persona and operational constraints.",
    )
    messages: list[ChatMessage] = Field(
        default_factory=list,
        description="Multi-turn conversation history if applicable.",
    )
    model: str | None = Field(
        default=None,
        description="Optional model override; defaults to provider default model.",
    )
    temperature: float | None = Field(
        default=None,
        ge=0.0,
        le=2.0,
        description="Optional sampling temperature override.",
    )
    max_tokens: int | None = Field(
        default=None,
        gt=0,
        description="Optional maximum token budget for the completion.",
    )


class TokenUsage(BaseModel):
    """Token consumption metrics for an LLM interaction."""

    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)


class CompletionResponse(BaseModel):
    """Standardized response container for LLM completions."""

    content: str = Field(
        description="Generated text content from the LLM.",
    )
    model: str = Field(
        description="Model identifier that produced this completion.",
    )
    provider: str = Field(
        description="Provider name that serviced the request.",
    )
    usage: TokenUsage = Field(
        default_factory=TokenUsage,
        description="Token usage metrics.",
    )
    raw_response: dict[str, Any] | None = Field(
        default=None,
        description="Raw response payload from the provider SDK for debugging.",
    )


class BaseLLMProvider(ABC):
    """Abstract base class establishing the interface for all LLM providers."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the unique identifier string for this provider backend."""
        ...

    @property
    @abstractmethod
    def default_model(self) -> str:
        """Return the default model name for this provider."""
        ...

    @abstractmethod
    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        """Execute an asynchronous text completion against the provider.

        Args:
            request: The completion request parameters.

        Returns:
            A standardized CompletionResponse.

        Raises:
            ProviderError: If the completion fails during execution.
        """
        ...

    @abstractmethod
    async def generate_structured(
        self,
        schema: type[T],
        request: CompletionRequest,
    ) -> T:
        """Generate a structured response adhering strictly to a Pydantic schema.

        Args:
            schema: The Pydantic model class to validate the response against.
            request: The completion request parameters.

        Returns:
            An instance of the requested schema type T.

        Raises:
            ProviderError: If structured generation or validation fails.
        """
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Verify provider availability and configuration without substantial token usage.

        Returns:
            True if the provider is operational, False otherwise.
        """
        ...
