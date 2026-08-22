"""Factory for initializing LLM providers."""

from mugiwara.core.config import LLMConfig, LLMProviderType
from mugiwara.core.exceptions import ProviderNotSupportedError
from mugiwara.providers.base import BaseLLMProvider
from mugiwara.providers.mock import MockLLMProvider


def get_provider(config: LLMConfig) -> BaseLLMProvider:
    """Return an initialized LLM provider instance matching configuration.

    Args:
        config: LLM configuration containing provider type and model settings.

    Returns:
        An operational BaseLLMProvider implementation.

    Raises:
        ProviderNotSupportedError: If a real/unsupported provider is requested before its phase.
    """
    if config.provider == LLMProviderType.MOCK:
        return MockLLMProvider(default_model=config.model)

    if config.provider in (
        LLMProviderType.OPENAI,
        LLMProviderType.ANTHROPIC,
        LLMProviderType.GEMINI,
        LLMProviderType.OLLAMA,
    ):
        msg = (
            f"Provider '{config.provider.value}' is deferred to a future phase. "
            f"Set provider to 'mock' for testing in the current phase."
        )
        raise ProviderNotSupportedError(msg)

    msg = f"Unsupported provider type '{config.provider}'."
    raise ProviderNotSupportedError(msg)
