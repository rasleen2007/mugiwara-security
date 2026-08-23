"""LLM provider abstraction layer for Mugiwara Security."""

from mugiwara.providers.base import (
    BaseLLMProvider,
    ChatMessage,
    CompletionRequest,
    CompletionResponse,
    TokenUsage,
)
from mugiwara.providers.factory import get_provider
from mugiwara.providers.mock import MockLLMProvider
from mugiwara.providers.ollama import DEFAULT_OLLAMA_BASE_URL, OllamaProvider
from mugiwara.providers.transport import Transport, TransportError, UrllibTransport

__all__ = [
    "DEFAULT_OLLAMA_BASE_URL",
    "BaseLLMProvider",
    "ChatMessage",
    "CompletionRequest",
    "CompletionResponse",
    "MockLLMProvider",
    "OllamaProvider",
    "TokenUsage",
    "Transport",
    "TransportError",
    "UrllibTransport",
    "get_provider",
]
