"""Safe source-project intake for authorized local analysis."""

from mugiwara.intake.project import (
    DisposableIntake,
    IntakeLimits,
    IntakeTarget,
    open_directory_target,
    open_zip_target,
)

__all__ = [
    "DisposableIntake",
    "IntakeLimits",
    "IntakeTarget",
    "open_directory_target",
    "open_zip_target",
]
