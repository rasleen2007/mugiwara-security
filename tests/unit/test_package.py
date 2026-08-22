"""Unit tests verifying package metadata and basic entrypoint."""

from typer.testing import CliRunner

import mugiwara
from mugiwara.cli.main import app


def test_version(sample_version: str) -> None:
    """Verify that mugiwara version is defined and matches expected version."""
    assert mugiwara.__version__ == sample_version


def test_author() -> None:
    """Verify that author metadata is present."""
    assert "Mugiwara Security Contributors" in mugiwara.__author__


def test_main_entrypoint() -> None:
    """Verify that CLI entrypoint runs and displays help banner."""
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Mugiwara Security" in result.stdout
