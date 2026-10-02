from __future__ import annotations

import json
from pathlib import Path, PurePosixPath

MANIFEST_VERSION = 3
RETIRED_FIELDS = {
    "files",
    "optional_registry_artifacts_published",
    "optional_artifacts_published",
}


def _validate_paths(
    root: Path,
    values: object,
    label: str,
    errors: list[str],
) -> set[str]:
    if not isinstance(values, list):
        errors.append(f"generated-artifacts.json:{label}: must be an array")
        return set()

    seen: set[str] = set()
    for index, value in enumerate(values):
        item_label = f"generated-artifacts.json:{label}[{index}]"
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{item_label}: must be a non-empty string")
            continue

        rel = PurePosixPath(value)
        if rel.is_absolute() or ".." in rel.parts:
            errors.append(f"{item_label}: must stay inside the publication directory")
            continue
        normalized = rel.as_posix()
        if normalized in seen:
            errors.append(f"{item_label}: duplicate path {normalized}")
            continue
        seen.add(normalized)

        if not (root / Path(*rel.parts)).exists():
            errors.append(f"{item_label}: listed artifact does not exist: {normalized}")

    return seen


def validate_generated_manifest(root: Path) -> list[str]:
    """Validate the current fail-closed generated-artifacts.json contract."""

    manifest_path = root / "generated-artifacts.json"
    if not manifest_path.is_file():
        return ["missing generated-artifacts.json publication manifest"]

    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"generated-artifacts.json: {exc}"]
    if not isinstance(data, dict):
        return ["generated-artifacts.json: root must be an object"]

    errors: list[str] = []
    if data.get("manifest_version") != MANIFEST_VERSION:
        errors.append(
            "generated-artifacts.json: manifest_version must be "
            f"{MANIFEST_VERSION}"
        )

    for field in sorted(RETIRED_FIELDS):
        if field in data:
            errors.append(
                f"generated-artifacts.json: retired field {field!r} is not allowed"
            )

    _validate_paths(root, data.get("artifacts"), "artifacts", errors)

    if data.get("canonical_registry_published") is not True:
        errors.append(
            "generated-artifacts.json: canonical_registry_published must be true"
        )

    return errors
