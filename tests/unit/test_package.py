"""Unit tests verifying package metadata and basic entrypoint."""

import re
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as distribution_version

import pytest
from typer.testing import CliRunner

import mugiwara
from mugiwara.cli.main import app
from mugiwara.models.report import ScanReport

_SEMVER_PATTERN = re.compile(r"^\d+\.\d+\.\d+(?:[.+][0-9A-Za-z.-]+)?$")


def test_version_shape() -> None:
    """Verify that mugiwara exposes a semantic version string."""
    assert _SEMVER_PATTERN.match(mugiwara.__version__)


def test_version_matches_distribution_metadata() -> None:
    """Verify the runtime version agrees with installed distribution metadata."""
    try:
        metadata_version = distribution_version("mugiwara")
    except PackageNotFoundError:
        pytest.skip("mugiwara distribution is not installed")
    assert mugiwara.__version__ == metadata_version


def test_scan_report_default_version_tracks_package() -> None:
    """Verify new reports are stamped with the running tool version by default."""
    report = ScanReport(target_path="example")
    assert report.mugiwara_version == mugiwara.__version__


def test_author() -> None:
    """Verify that author metadata is present."""
    assert "Mugiwara Security Contributors" in mugiwara.__author__


def test_main_entrypoint() -> None:
    """Verify that CLI entrypoint runs and displays help banner."""
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Mugiwara Security" in result.stdout
