"""Entrypoint module for python -m mugiwara."""

from mugiwara.cli.main import app


def main() -> None:
    """Entry point for the Mugiwara Security application."""
    app()


if __name__ == "__main__":
    main()
