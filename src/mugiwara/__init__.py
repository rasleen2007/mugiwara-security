"""Mugiwara Security — Autonomous AI-Powered Security Verification Platform."""

from contextlib import suppress
from importlib.metadata import PackageNotFoundError, version

# Single source of truth: packaging (hatchling dynamic version) parses the
# literal below; installed distributions take precedence at runtime.
__version__ = "0.1.0"

with suppress(PackageNotFoundError):
    __version__ = version("mugiwara")

__author__ = "Mugiwara Security Contributors"

__all__ = ["__author__", "__version__"]
