"""Global pytest configuration and fixtures."""

import pytest


@pytest.fixture
def sample_version() -> str:
    """Fixture providing expected project version string."""
    return "0.1.0"
