from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath

MANIFEST_VERSION = 3
EXPECTED_SOURCE = "genshinre.artifactpublish"
EXPECTED_STATUS = "generated-artifacts-published"
HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
RETIRED_FIELDS = {
    "files",
    "optional_registry_artifacts_published",
    "optional_artifacts_published",
}
REQUIRED_METADATA_COUNTS = (
    "types",
    "fields",
    "methods",
    "method_pointers",
)
REQUIRED_PUBLICATION_ROWS = (
    "metadata/types.csv",
    "metadata/fields.csv",
    "metadata/methods.csv",
    "metadata/method-pointers.csv",
    "metadata/runtime-types.csv",
)
SAMPLE_HASH_MAP = {
    "exe_sha256": "GenshinImpact.exe",
    "metadata_sha256": "global-metadata.dat",
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


def _load_hash_samples(root: Path, errors: list[str]) -> dict[str, object] | None:
    hashes_path = root / "hashes.json"
    if not hashes_path.is_file():
        errors.append("generated-artifacts.json: hashes.json is required for publication provenance")
        return None
    try:
        data = json.loads(hashes_path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"generated-artifacts.json: cannot read hashes.json: {exc}")
        return None
    if not isinstance(data, dict):
        errors.append("generated-artifacts.json: hashes.json root must be an object")
        return None
    samples = data.get("samples")
    if not isinstance(samples, dict):
        errors.append("generated-artifacts.json: hashes.json.samples must be an object")
        return None
    return samples


def _validate_positive_int_map(
    value: object,
    label: str,
    required_keys: tuple[str, ...],
    errors: list[str],
) -> dict[str, int] | None:
    if not isinstance(value, dict):
        errors.append(f"{label}: must be an object")
        return None
    result: dict[str, int] = {}
    for key in required_keys:
        item = value.get(key)
        if isinstance(item, bool) or not isinstance(item, int) or item <= 0:
            errors.append(f"{label}.{key}: must be a positive integer")
            continue
        result[key] = item
    return result


def _validate_sample_provenance(
    root: Path,
    validation: dict[str, object],
    errors: list[str],
) -> None:
    sample = validation.get("sample")
    if not isinstance(sample, dict):
        errors.append("generated-artifacts.json: validation.sample must be an object")
        return

    hash_samples = _load_hash_samples(root, errors)
    for manifest_key, sample_name in SAMPLE_HASH_MAP.items():
        value = sample.get(manifest_key)
        if not isinstance(value, str) or not HEX64.fullmatch(value):
            errors.append(
                f"generated-artifacts.json: validation.sample.{manifest_key} must be a SHA-256"
            )
            continue
        if hash_samples is None:
            continue
        sample_entry = hash_samples.get(sample_name)
        if not isinstance(sample_entry, dict):
            errors.append(
                f"generated-artifacts.json: hashes.json.samples missing {sample_name}"
            )
            continue
        expected = sample_entry.get("sha256")
        if not isinstance(expected, str) or not HEX64.fullmatch(expected):
            errors.append(
                f"generated-artifacts.json: hashes.json sample {sample_name} has invalid sha256"
            )
            continue
        if value.lower() != expected.lower():
            errors.append(
                f"generated-artifacts.json: validation.sample.{manifest_key} does not match hashes.json"
            )


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
    if data.get("source") != EXPECTED_SOURCE:
        errors.append(
            f"generated-artifacts.json: source must be {EXPECTED_SOURCE}"
        )
    if data.get("status") != EXPECTED_STATUS:
        errors.append(
            f"generated-artifacts.json: status must be {EXPECTED_STATUS}"
        )

    for field in sorted(RETIRED_FIELDS):
        if field in data:
            errors.append(
                f"generated-artifacts.json: retired field {field!r} is not allowed"
            )

    artifacts = _validate_paths(root, data.get("artifacts"), "artifacts", errors)

    if data.get("canonical_registry_published") is not True:
        errors.append(
            "generated-artifacts.json: canonical_registry_published must be true"
        )

    validation = data.get("validation")
    metadata_counts: dict[str, int] | None = None
    if not isinstance(validation, dict):
        errors.append("generated-artifacts.json: validation must be an object")
    else:
        metadata_counts = _validate_positive_int_map(
            validation.get("metadata_counts"),
            "generated-artifacts.json: validation.metadata_counts",
            REQUIRED_METADATA_COUNTS,
            errors,
        )
        if validation.get("runtime_type_anchor") is not True:
            errors.append(
                "generated-artifacts.json: validation.runtime_type_anchor must be true"
            )
        if validation.get("getcmdid_anchor") is not True:
            errors.append(
                "generated-artifacts.json: validation.getcmdid_anchor must be true"
            )
        _validate_sample_provenance(root, validation, errors)

    publication = data.get("publication")
    publication_rows: dict[str, int] | None = None
    if not isinstance(publication, dict):
        errors.append("generated-artifacts.json: publication must be an object")
    else:
        if publication.get("metadata_format") != "compact-query-indexes":
            errors.append(
                "generated-artifacts.json: publication.metadata_format must be compact-query-indexes"
            )
        publication_rows = _validate_positive_int_map(
            publication.get("metadata_rows"),
            "generated-artifacts.json: publication.metadata_rows",
            REQUIRED_PUBLICATION_ROWS,
            errors,
        )

    for rel in REQUIRED_PUBLICATION_ROWS:
        if rel not in artifacts:
            errors.append(
                f"generated-artifacts.json: canonical publication artifact missing from artifacts: {rel}"
            )

    if metadata_counts is not None and publication_rows is not None:
        crosswalk = {
            "types": "metadata/types.csv",
            "fields": "metadata/fields.csv",
            "methods": "metadata/methods.csv",
            "method_pointers": "metadata/method-pointers.csv",
        }
        for count_key, rel in crosswalk.items():
            left = metadata_counts.get(count_key)
            right = publication_rows.get(rel)
            if left is not None and right is not None and left != right:
                errors.append(
                    "generated-artifacts.json: validation/publication row count mismatch "
                    f"for {rel}: {left} != {right}"
                )

    return errors
