from __future__ import annotations

from pathlib import Path

from .artifactmanifest import validate_generated_manifest
from .cmdobservations import (
    validate_confirmed_semantic_alignment,
    validate_observation_summary,
)
from .validate import validate_version as validate_core_version
from .xrefartifacts import XREF_TABLE_CONTRACTS, validate_xref_table


def _extend_unique(target: list[str], values: list[str]) -> None:
    seen = set(target)
    for value in values:
        if value not in seen:
            target.append(value)
            seen.add(value)


def validate_version(path: Path, allow_partial: bool = False) -> tuple[list[str], list[str]]:
    """Run the maintained version-tree validation surface.

    The original validator still owns registry/proto/analysis checks. This layer
    composes the newer artifact contracts so callers have one stable entry point
    without coupling validator-only changes to exact-sample regeneration.
    """

    errors, warnings = validate_core_version(path, allow_partial=allow_partial)

    manifest = path / "generated-artifacts.json"
    if manifest.is_file():
        _extend_unique(errors, validate_generated_manifest(path))

    observations = path / "cmdids" / "observations.csv"
    known_opcodes = path / "proto" / "known-opcodes.csv"
    if observations.is_file():
        _extend_unique(errors, validate_observation_summary(observations))
        if known_opcodes.is_file():
            _extend_unique(
                errors,
                validate_confirmed_semantic_alignment(observations, known_opcodes),
            )

    xref_dir = path / "xrefs"
    for filename in XREF_TABLE_CONTRACTS:
        table = xref_dir / filename
        if table.is_file():
            _extend_unique(errors, validate_xref_table(table))

    return errors, warnings
