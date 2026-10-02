from __future__ import annotations

from . import cli
from .versionvalidate import validate_version


def main() -> None:
    # Keep the existing parser/command dispatch untouched while replacing only the
    # version-validation implementation with the maintained composed validator.
    cli.validate_version = validate_version
    cli.main()
