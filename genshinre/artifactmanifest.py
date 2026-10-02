from __future__ import annotations

import json
from pathlib import Path, PurePosixPath

MANIFEST_VERSION = 2


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
    """Validate the current generated-artifacts.json publication contract.

    This deliberately validates only the manifest's own structure/path contract.
    Dataset-specific publication gates remain owned by their corresponding
    validators/publishers.
    """

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

    if "files" in data:
        errors.append("generated-artifacts.json: legacy field 'files' is not allowed in manifest v2")
    if "optional_registry_artifacts_published" in data:
        errors.append(
            "generated-artifacts.json: legacy field "
            "'optional_registry_artifacts_published' is not allowed in manifest v2"
        )

    artifacts = _validate_paths(root, data.get("artifacts"), "artifacts", errors)
    optional = _validate_paths(
        root,
        data.get("optional_artifacts_published", []),
        "optional_artifacts_published",
        errors,
    )

    outside = sorted(optional - artifacts)
    if outside:
        errors.append(
            "generated-artifacts.json: optional_artifacts_published must be a subset "
            f"of artifacts; outside={outside}"
        )

    if not isinstance(data.get("canonical_registry_published"), bool):
        errors.append(
            "generated-artifacts.json: canonical_registry_published must be a boolean"
        )

    return errors
