"""Subcommands for Mugiwara Security CLI."""

from mugiwara.cli.commands.config import config_app
from mugiwara.cli.commands.fix import fix_command
from mugiwara.cli.commands.init import init_command
from mugiwara.cli.commands.report import report_app
from mugiwara.cli.commands.sandbox import sandbox_app
from mugiwara.cli.commands.scan import scan_command

__all__ = [
    "config_app",
    "fix_command",
    "init_command",
    "report_app",
    "sandbox_app",
    "scan_command",
]
