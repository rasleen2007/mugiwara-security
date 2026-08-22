"""Base agent abstraction, shared session context, and LLM interaction helpers."""

import math
from abc import ABC, abstractmethod
from typing import Any, TypeVar

from pydantic import BaseModel

from mugiwara.agents.budget import TokenBudget
from mugiwara.agents.models import AgentDiagnostics, AttackSurfaceMap
from mugiwara.agents.prompts import PromptManager
from mugiwara.agents.sources import CollectedSources, SourceFile
from mugiwara.core.config import MugiwaraSettings
from mugiwara.core.exceptions import AgentExecutionError
from mugiwara.providers.base import BaseLLMProvider, CompletionRequest

T = TypeVar("T", bound=BaseModel)

_ESTIMATED_CHARS_PER_TOKEN = 4

_CORRECTION_SUFFIX = (
    "\n\nIMPORTANT: Your previous reply could not be parsed as a valid "
    "response. Reply again with ONLY raw JSON that validates against the "
    "requested schema and references only the paths supplied above."
)

_MAX_STRUCTURED_ATTEMPTS = 2


def estimate_text_tokens(text: str) -> int:
    """Estimate the token count of a text block, rounding conservatively upward.

    Structured generation does not surface provider usage metrics through the
    Phase 1 protocol, so budgets are enforced using an upper-bound character
    estimate. This intentionally over-counts rather than under-counts.

    Args:
        text: Arbitrary prompt or response text.

    Returns:
        Estimated number of tokens (never zero).
    """
    return max(1, math.ceil(len(text) / _ESTIMATED_CHARS_PER_TOKEN))


class AgentContext:
    """Shared per-session state handed to every agent.

    Holds the provider, configuration, preloaded sources, token budget,
    prompt manager, and mutable diagnostics. Agents never read the target
    filesystem; they work exclusively against ``sources``.
    """

    def __init__(
        self,
        provider: BaseLLMProvider,
        settings: MugiwaraSettings,
        sources: CollectedSources,
        target_root: str,
    ) -> None:
        """Build the context for one scan session.

        Args:
            provider: The configured LLM provider backend.
            settings: Active application settings.
            sources: Preloaded collection of target files.
            target_root: Resolved scan target root path.
        """
        self.provider = provider
        self.settings = settings
        self.sources = sources
        self.target_root = target_root
        self.attack_surface: AttackSurfaceMap | None = None
        self.budget = TokenBudget(settings.agents.max_total_tokens)
        self.prompts = PromptManager()
        self.diagnostics = AgentDiagnostics(
            files_collected=len(sources.files),
            secret_markers_found=len(sources.secret_markers),
        )
        self.source_index: dict[str, SourceFile] = {
            source.relative_path: source for source in sources.files
        }

    @property
    def source_paths(self) -> frozenset[str]:
        """Return the set of collected relative paths available to agents."""
        return frozenset(self.source_index)


class BaseAgent(ABC):
    """Abstract base class for all security agents."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the unique agent identifier used in logs and diagnostics."""
        ...

    @abstractmethod
    async def run(self, ctx: AgentContext) -> Any:
        """Execute the agent phase.

        Args:
            ctx: Shared session context.

        Returns:
            A structured result specific to the concrete agent (a Pydantic
            model for recon, a finding list for discovery).
        """
        ...

    async def _request_structured(
        self,
        ctx: AgentContext,
        schema: type[T],
        prompt_name: str,
        **variables: str,
    ) -> T:
        """Render a registered prompt and obtain a schema-validated response.

        Enforces the session token budget before each call (conservatively
        reserving the configured completion allowance), records estimated
        spend afterwards, and performs exactly one corrective retry when the
        first reply fails validation.

        Args:
            ctx: Shared session context.
            schema: Pydantic model the response must satisfy.
            prompt_name: Registered template key.
            **variables: Template variables.

        Returns:
            A validated instance of ``schema``.

        Raises:
            AgentExecutionError: If rendering or validation ultimately fails.
        """
        try:
            system_prompt, user_prompt = ctx.prompts.render(prompt_name, **variables)
        except Exception as exc:
            msg = f"[{self.name}] prompt rendering failed: {exc}"
            raise AgentExecutionError(msg) from exc

        completion_allowance = ctx.settings.llm.max_tokens or 0
        last_error: Exception | None = None
        current_user = user_prompt
        for _ in range(_MAX_STRUCTURED_ATTEMPTS):
            estimated = (
                estimate_text_tokens(system_prompt)
                + estimate_text_tokens(current_user)
                + completion_allowance
            )
            ctx.budget.ensure_can_spend(estimated)
            request = CompletionRequest(
                prompt=current_user,
                system_prompt=system_prompt,
                model=ctx.settings.llm.model,
                temperature=ctx.settings.llm.temperature,
                max_tokens=ctx.settings.llm.max_tokens,
            )
            ctx.diagnostics.llm_calls += 1
            try:
                validated = await ctx.provider.generate_structured(schema, request)
            except Exception as exc:
                last_error = exc
                current_user = user_prompt + _CORRECTION_SUFFIX
                continue
            actual = estimate_text_tokens(system_prompt) + estimate_text_tokens(current_user)
            if isinstance(validated, BaseModel):
                actual += estimate_text_tokens(validated.model_dump_json())
            ctx.budget.record_usage(actual)
            ctx.diagnostics.tokens_used = ctx.budget.used_tokens
            return validated

        msg = f"[{self.name}] structured generation failed after retries: {last_error}"
        raise AgentExecutionError(msg) from last_error
