"""Unit tests verifying package metadata and basic entrypoint."""

import pytest

import mugiwara
from mugiwara.__main__ import main


def test_version(sample_version: str) -> None:
    """Verify that mugiwara version is defined and matches expected version."""
    assert mugiwara.__version__ == sample_version


def test_author() -> None:
    """Verify that author metadata is present."""
    assert "Mugiwara Security Contributors" in mugiwara.__author__


def test_main_entrypoint(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify that __main__.main executes without error and prints banner."""
    main()
    captured = capsys.readouterr()
    assert "Mugiwara Security v0.1.0" in captured.out
