"""Local Ollama LLM provider.

Talks to a user-configured, locally running Ollama daemon (default
``http://127.0.0.1:11434``) through the pinned :class:`UrllibTransport`.
Every request URL is built solely from the configured base URL plus fixed
API paths, so neither prompt content nor server responses can redirect
traffic anywhere else.

Structured generation keeps the provider-layer contract used across the
project: the model is instructed to emit a single JSON object (Ollama's
``format: "json"`` mode), the reply is extracted defensively (raw JSON,
fenced code block, or embedded object), and validated against the requested
Pydantic schema - failures raise :class:`ProviderExecutionError` exactly as
the mock provider does.
"""

import asyncio
import json
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from mugiwara.core.config import LLMConfig
from mugiwara.core.exceptions import ProviderExecutionError
from mugiwara.providers.base import (
    BaseLLMProvider,
    CompletionRequest,
    CompletionResponse,
    TokenUsage,
)
from mugiwara.providers.egress import (
    DEFAULT_OLLAMA_LOCAL_BASE,
    ensure_provider_egress_allowed,
    is_local_http_url,
    redact_source_secrets,
    resolve_provider_base_url,
)
from mugiwara.providers.transport import Transport, TransportError, UrllibTransport

T = TypeVar("T", bound=BaseModel)

DEFAULT_OLLAMA_BASE_URL = DEFAULT_OLLAMA_LOCAL_BASE

_STRUCTURED_INSTRUCTION = (
    "You must respond with exactly one JSON object and nothing else. "
    "No prose, no explanations, no markdown fences. "
    "The JSON object must conform to this schema:\n"
)


def extract_json_object(text: str) -> dict[str, Any]:
    """Extract the first JSON object from raw model output.

    Handles plain JSON, markdown-fenced JSON, and JSON embedded in
    surrounding prose.

    Args:
        text: Raw completion content.

    Returns:
        The decoded JSON object.

    Raises:
        ProviderExecutionError: If no decodable JSON object is present.
    """
    stripped = text.strip()
    if stripped.startswith("```"):
        first_newline = stripped.find("\n")
        if first_newline != -1:
            stripped = stripped[first_newline + 1 :]
        if stripped.rstrip().endswith("```"):
            stripped = stripped.rstrip()[:-3]
        stripped = stripped.strip()
    try:
        decoded = json.loads(stripped)
        if isinstance(decoded, dict):
            return decoded
    except json.JSONDecodeError:
        pass

    depth = 0
    start = -1
    for index, char in enumerate(stripped):
        if char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}" and depth > 0:
            depth -= 1
            if depth == 0 and start != -1:
                candidate = stripped[start : index + 1]
                try:
                    decoded = json.loads(candidate)
                except json.JSONDecodeError:
                    continue
                if isinstance(decoded, dict):
                    return decoded
    msg = "Model response did not contain a usable JSON object."
    raise ProviderExecutionError(msg)


class OllamaProvider(BaseLLMProvider):
    """Provider implementation for a locally running Ollama daemon."""

    def __init__(self, config: LLMConfig, transport: Transport | None = None) -> None:
        """Build the provider from LLM configuration.

        Args:
            config: LLM settings; ``api_base`` overrides the local endpoint.
            transport: Optional transport override (tests inject fakes here).
        """
        self._config = config
        self._base_url = ensure_provider_egress_allowed(config, resolve_provider_base_url(config))
        self._chat_endpoint = f"{self._base_url}/api/chat"
        self._tags_endpoint = f"{self._base_url}/api/tags"
        self._transport: Transport = transport or UrllibTransport(self._base_url)
        self._timeout_seconds = config.timeout_seconds
        # Only the consented non-local path pays redaction cost; loopback
        # analysis keeps full-fidelity prompts.
        self._redact_outbound = not is_local_http_url(self._base_url)

    @property
    def provider_name(self) -> str:
        """Return provider identifier string."""
        return "ollama"

    @property
    def default_model(self) -> str:
        """Return the configured model name."""
        return self._config.model

    async def complete(
        self,
        request: CompletionRequest,
        *,
        json_mode: bool = False,
    ) -> CompletionResponse:
        """Execute a chat completion against the local Ollama daemon.

        Args:
            request: The completion request parameters.
            json_mode: When True, asks Ollama for valid-JSON-only output;
                used internally by :meth:`generate_structured`.
        """
        messages: list[dict[str, str]] = []
        if request.system_prompt is not None:
            messages.append(
                {"role": "system", "content": self._maybe_redact(request.system_prompt)}
            )
        if request.prompt:
            messages.append({"role": "user", "content": self._maybe_redact(request.prompt)})
        messages.extend(
            {"role": m.role, "content": self._maybe_redact(m.content)} for m in request.messages
        )

        payload: dict[str, Any] = {
            "model": request.model or self.default_model,
            "messages": messages,
            "stream": False,
            "options": self._build_options(request),
        }
        if json_mode:
            payload["format"] = "json"
        data = await self._post(self._chat_endpoint, payload)

        content = str(data.get("message", {}).get("content", ""))
        prompt_tokens = int(data.get("prompt_eval_count") or 0)
        completion_tokens = int(data.get("eval_count") or 0)
        return CompletionResponse(
            content=content,
            model=str(data.get("model", payload["model"])),
            provider=self.provider_name,
            usage=TokenUsage(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=prompt_tokens + completion_tokens,
            ),
            raw_response=data,
        )

    async def generate_structured(
        self,
        schema: type[T],
        request: CompletionRequest,
    ) -> T:
        """Generate one JSON object and validate it against ``schema``."""
        schema_json = json.dumps(schema.model_json_schema(), indent=2)
        structured_request = request.model_copy(deep=True)
        instruction = (
            f"{request.system_prompt}\n\n{schema_json}"
            if request.system_prompt is not None
            else schema_json
        )
        structured_request.system_prompt = (
            f"{_STRUCTURED_INSTRUCTION}{instruction}\nRespond with the JSON object only."
        )

        response = await self.complete(structured_request, json_mode=True)
        decoded = extract_json_object(response.content)
        try:
            return schema.model_validate(decoded)
        except ValidationError as exc:
            msg = (
                f"Ollama response failed schema validation for "
                f"'{schema.__name__}': {exc.error_count()} error(s)."
            )
            raise ProviderExecutionError(msg) from exc

    async def health_check(self) -> bool:
        """Return True when the local daemon answers its tag listing."""
        try:
            await asyncio.to_thread(self._transport.get_json, self._tags_endpoint, 5.0)
        except TransportError:
            return False
        return True

    async def _post(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        """POST via the pinned transport, offloading blocking I/O."""
        try:
            return await asyncio.to_thread(
                self._transport.post_json,
                url,
                payload,
                self._timeout_seconds,
            )
        except TransportError as exc:
            msg = f"Ollama request failed: {exc}"
            raise ProviderExecutionError(msg) from exc

    def _maybe_redact(self, text: str) -> str:
        """Screen outbound text for secrets on the non-local path only."""
        if self._redact_outbound:
            return redact_source_secrets(text)
        return text

    def _build_options(self, request: CompletionRequest) -> dict[str, Any]:
        """Merge request parameters with configured defaults for Ollama."""
        temperature = (
            request.temperature if request.temperature is not None else self._config.temperature
        )
        max_tokens = (
            request.max_tokens if request.max_tokens is not None else self._config.max_tokens
        )
        options: dict[str, Any] = {"temperature": temperature}
        if max_tokens is not None:
            options["num_predict"] = max_tokens
        return options
