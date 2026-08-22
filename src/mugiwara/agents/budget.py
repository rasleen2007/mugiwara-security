"""Session-scoped LLM token budget tracking for agent orchestration."""

from mugiwara.core.exceptions import TokenBudgetExceededError
from mugiwara.providers.base import TokenUsage


class TokenBudget:
    """Conservative, configurable cumulative token budget for one scan session.

    The budget is checked *before* each LLM call and updated with the usage
    reported by the provider afterwards, so an unattended scan can never incur
    unbounded token costs.
    """

    def __init__(self, max_total_tokens: int) -> None:
        """Initialize the budget.

        Args:
            max_total_tokens: Cumulative prompt + completion tokens allowed.

        Raises:
            ValueError: If ``max_total_tokens`` is not strictly positive.
        """
        if max_total_tokens <= 0:
            msg = f"max_total_tokens must be positive, got {max_total_tokens}."
            raise ValueError(msg)
        self._max_total_tokens = max_total_tokens
        self._used_tokens = 0

    @property
    def max_total_tokens(self) -> int:
        """Return the configured budget ceiling."""
        return self._max_total_tokens

    @property
    def used_tokens(self) -> int:
        """Return tokens consumed so far."""
        return self._used_tokens

    @property
    def remaining_tokens(self) -> int:
        """Return the number of tokens still available."""
        return max(0, self._max_total_tokens - self._used_tokens)

    @property
    def is_exhausted(self) -> bool:
        """Return whether any further LLM spend would breach the budget."""
        return self.remaining_tokens <= 0

    def ensure_can_spend(self, estimated_tokens: int = 1) -> None:
        """Verify that a prospective LLM call fits within the remaining budget.

        Args:
            estimated_tokens: Lower-bound token estimate for the upcoming call.

        Raises:
            TokenBudgetExceededError: If spending would exceed the budget.
        """
        if estimated_tokens < 1:
            estimated_tokens = 1
        if self.remaining_tokens < estimated_tokens:
            msg = (
                f"Token budget exhausted: used {self._used_tokens} of "
                f"{self._max_total_tokens} allowed tokens; refusing an estimated "
                f"{estimated_tokens}-token call."
            )
            raise TokenBudgetExceededError(msg)

    def record_usage(self, tokens: int) -> int:
        """Accumulate a raw token amount against the budget.

        Args:
            tokens: Number of tokens to add (negative values are ignored).

        Returns:
            The updated cumulative token count.
        """
        if tokens > 0:
            self._used_tokens += tokens
        return self._used_tokens

    def record(self, usage: TokenUsage) -> int:
        """Accumulate provider-reported usage metrics against the budget.

        Args:
            usage: Token metrics from a completion response.

        Returns:
            The updated cumulative token count.
        """
        return self.record_usage(usage.total_tokens)
