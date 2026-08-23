"""Factory for initializing LLM providers.

Egress policy: every provider endpoint must be on the local machine unless
the user explicitly set ``llm.allow_remote: true``. The Ollama provider
enforces this itself when constructed (so it also holds for direct
instantiation), and remote cloud providers fail closed here regardless of
consent because no client implementation exists yet.
"""

from mugiwara.core.config import LLMConfig, LLMProviderType
from mugiwara.core.exceptions import ProviderNotSupportedError
from mugiwara.providers.base import BaseLLMProvider
from mugiwara.providers.mock import MockLLMProvider
from mugiwara.providers.ollama import OllamaProvider

_REMOTE_CLOUD_PROVIDERS = (
    LLMProviderType.OPENAI,
    LLMProviderType.ANTHROPIC,
    LLMProviderType.GEMINI,
)


def get_provider(config: LLMConfig) -> BaseLLMProvider:
    """Return an initialized LLM provider instance matching configuration.

    Args:
        config: LLM configuration containing provider type, model settings,
            and the explicit ``allow_remote`` source-egress decision.

    Returns:
        An operational BaseLLMProvider implementation.

    Raises:
        RemoteProviderNotAuthorizedError: If the resolved endpoint is not on
            the local machine without explicit ``allow_remote`` consent.
        ProviderNotSupportedError: If a remote cloud provider is requested;
            no client implementation exists yet regardless of consent.
    """
    if config.provider == LLMProviderType.MOCK:
        return MockLLMProvider(default_model=config.model)

    if config.provider == LLMProviderType.OLLAMA:
        return OllamaProvider(config)

    if config.provider in _REMOTE_CLOUD_PROVIDERS:
        msg = (
            f"Remote cloud provider '{config.provider.value}' is not implemented "
            "yet and would send your source code off this machine. Mugiwara "
            "currently supports provider 'ollama' (local daemon) and 'mock' "
            "(deterministic)."
        )
        raise ProviderNotSupportedError(msg)

    msg = f"Unsupported provider type '{config.provider}'."
    raise ProviderNotSupportedError(msg)
