"""Unit tests for the session token budget tracker."""

import pytest

from mugiwara.agents.budget import TokenBudget
from mugiwara.core.exceptions import TokenBudgetExceededError
from mugiwara.providers.base import TokenUsage


def test_initial_state_reflects_full_budget() -> None:
    """Verify a fresh budget reports full remaining tokens."""
    budget = TokenBudget(max_total_tokens=1_000)

    assert budget.max_total_tokens == 1_000
    assert budget.used_tokens == 0
    assert budget.remaining_tokens == 1_000
    assert budget.is_exhausted is False


def test_invalid_configuration_rejected() -> None:
    """Verify non-positive budgets are rejected at construction."""
    with pytest.raises(ValueError, match="must be positive"):
        TokenBudget(max_total_tokens=0)


def test_record_usage_accumulates() -> None:
    """Verify raw usage amounts accumulate and return the new total."""
    budget = TokenBudget(max_total_tokens=500)

    assert budget.record_usage(120) == 120
    assert budget.record_usage(80) == 200
    assert budget.used_tokens == 200
    assert budget.remaining_tokens == 300


def test_record_token_usage_model_accumulates_total() -> None:
    """Verify TokenUsage models contribute their total token count."""
    budget = TokenBudget(max_total_tokens=500)

    budget.record(TokenUsage(prompt_tokens=30, completion_tokens=20, total_tokens=50))

    assert budget.used_tokens == 50


def test_negative_record_usage_ignored() -> None:
    """Verify negative raw amounts do not corrupt the counter."""
    budget = TokenBudget(max_total_tokens=100)

    budget.record_usage(-50)

    assert budget.used_tokens == 0


def test_ensure_can_spend_passes_within_limit() -> None:
    """Verify prospective calls within remaining budget are allowed."""
    budget = TokenBudget(max_total_tokens=1_000)
    budget.record_usage(400)

    budget.ensure_can_spend(600)


def test_exact_remaining_boundary_allowed() -> None:
    """Verify a call exactly matching remaining tokens is permitted."""
    budget = TokenBudget(max_total_tokens=1_000)

    budget.ensure_can_spend(1_000)


def test_exceeded_budget_raises_typed_error() -> None:
    """Verify exceeding the budget raises with diagnostic numbers."""
    budget = TokenBudget(max_total_tokens=1_000)
    budget.record_usage(900)

    with pytest.raises(TokenBudgetExceededError, match="used 900 of 1000"):
        budget.ensure_can_spend(200)


def test_zero_estimate_treated_as_minimum_one() -> None:
    """Verify zero/negative estimates are clamped to a one-token minimum."""
    exhausted = TokenBudget(max_total_tokens=1)
    exhausted.record_usage(1)

    with pytest.raises(TokenBudgetExceededError):
        exhausted.ensure_can_spend(0)
