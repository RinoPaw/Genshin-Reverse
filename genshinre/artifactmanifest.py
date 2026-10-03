from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath

from .nativeprofile import PROFILE_71
from .typearray import ENTRY_SIZE

MANIFEST_VERSION = 4
EXPECTED_SOURCE = "genshinre.artifactpublish"
EXPECTED_STATUS = "generated-artifacts-published"
EXPECTED_RUNTIME_STATUS = "canonical-exact-runtime-type-index"
HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
HEX_RVA = re.compile(r"^0x[0-9a-fA-F]+$")
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
CANONICAL_ARTIFACTS = (
    "metadata/fields.csv",
    "metadata/method-pointers.csv",
    "metadata/methods.csv",
    "metadata/native-decoder-summary.json",
    "metadata/runtime-types.csv",
    "metadata/runtime-types.summary.json",
    "metadata/type-methods.json",
    "metadata/types.csv",
    "registry/getcmdid-candidates.csv",
    "registry/getcmdid-candidates.summary.json",
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


def _load_json_object(path: Path, label: str, errors: list[str]) -> dict[str, object] | None:
    if not path.is_file():
        errors.append(f"{label}: required file is missing")
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        errors.append(f"{label}: cannot read JSON: {exc}")
        return None
    if not isinstance(data, dict):
        errors.append(f"{label}: root must be an object")
        return None
    return data


def _load_hash_samples(root: Path, errors: list[str]) -> dict[str, object] | None:
    data = _load_json_object(
        root / "hashes.json",
        "generated-artifacts.json: hashes.json",
        errors,
    )
    if data is None:
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
) -> dict[str, str] | None:
    sample = validation.get("sample")
    if not isinstance(sample, dict):
        errors.append("generated-artifacts.json: validation.sample must be an object")
        return None

    hash_samples = _load_hash_samples(root, errors)
    result: dict[str, str] = {}
    for manifest_key, sample_name in SAMPLE_HASH_MAP.items():
        value = sample.get(manifest_key)
        if not isinstance(value, str) or not HEX64.fullmatch(value):
            errors.append(
                f"generated-artifacts.json: validation.sample.{manifest_key} must be a SHA-256"
            )
            continue
        result[manifest_key] = value.lower()
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
    return result or None


def _parse_rva(value: object, label: str, errors: list[str]) -> int | None:
    if not isinstance(value, str) or not HEX_RVA.fullmatch(value):
        errors.append(f"{label}: must be a hexadecimal RVA")
        return None
    try:
        return int(value, 16)
    except ValueError:
        errors.append(f"{label}: must be a hexadecimal RVA")
        return None


def _validate_runtime_type_provenance(
    root: Path,
    validation: dict[str, object],
    publication_rows: dict[str, int] | None,
    sample_hashes: dict[str, str] | None,
    errors: list[str],
) -> None:
    expected_runtime_type_count = PROFILE_71.runtime_type_count
    count = validation.get("runtime_type_count")
    if isinstance(count, bool) or not isinstance(count, int):
        errors.append("generated-artifacts.json: validation.runtime_type_count must be an integer")
        manifest_count: int | None = None
    else:
        manifest_count = count
        if count != expected_runtime_type_count:
            errors.append(
                "generated-artifacts.json: validation.runtime_type_count must be "
                f"{expected_runtime_type_count}"
            )

    manifest_boundary = _parse_rva(
        validation.get("runtime_type_boundary_rva"),
        "generated-artifacts.json: validation.runtime_type_boundary_rva",
        errors,
    )
    if validation.get("runtime_type_boundary_verified") is not True:
        errors.append(
            "generated-artifacts.json: validation.runtime_type_boundary_verified must be true"
        )

    summary = _load_json_object(
        root / "metadata/runtime-types.summary.json",
        "generated-artifacts.json: metadata/runtime-types.summary.json",
        errors,
    )
    if summary is None:
        return

    if summary.get("status") != EXPECTED_RUNTIME_STATUS:
        errors.append(
            "generated-artifacts.json: runtime type summary status must be "
            f"{EXPECTED_RUNTIME_STATUS}"
        )
    if summary.get("structural_validation_passed") is not True:
        errors.append(
            "generated-artifacts.json: runtime type summary structural_validation_passed must be true"
        )
    if summary.get("boundary_entry_valid_type") is not False:
        errors.append(
            "generated-artifacts.json: runtime type boundary entry must fail the Il2CppType structural gate"
        )
    if summary.get("anchor_405772_class_84249_DMMJNICDOHM") is not True:
        errors.append(
            "generated-artifacts.json: runtime type summary lost the 405772 -> DMMJNICDOHM anchor"
        )

    summary_count = summary.get("runtime_type_count")
    if isinstance(summary_count, bool) or not isinstance(summary_count, int):
        errors.append(
            "generated-artifacts.json: runtime type summary runtime_type_count must be an integer"
        )
        summary_count_int: int | None = None
    else:
        summary_count_int = summary_count
        if summary_count != expected_runtime_type_count:
            errors.append(
                "generated-artifacts.json: runtime type summary count must be "
                f"{expected_runtime_type_count}"
            )
        if manifest_count is not None and summary_count != manifest_count:
            errors.append(
                "generated-artifacts.json: runtime type count disagrees with runtime-types.summary.json"
            )

    summary_type_array = _parse_rva(
        summary.get("type_array_rva"),
        "generated-artifacts.json: runtime type summary type_array_rva",
        errors,
    )
    summary_boundary = _parse_rva(
        summary.get("boundary_rva"),
        "generated-artifacts.json: runtime type summary boundary_rva",
        errors,
    )
    if (
        summary_type_array is not None
        and summary_boundary is not None
        and summary_count_int is not None
        and summary_boundary != summary_type_array + summary_count_int * ENTRY_SIZE
    ):
        errors.append(
            "generated-artifacts.json: runtime type boundary does not equal "
            "type_array_rva + runtime_type_count * 16"
        )
    if (
        manifest_boundary is not None
        and summary_boundary is not None
        and manifest_boundary != summary_boundary
    ):
        errors.append(
            "generated-artifacts.json: runtime type boundary disagrees with runtime-types.summary.json"
        )

    boundary_hex = summary.get("boundary_entry_hex")
    if (
        not isinstance(boundary_hex, str)
        or len(boundary_hex) != ENTRY_SIZE * 2
        or re.fullmatch(r"[0-9a-fA-F]+", boundary_hex) is None
    ):
        errors.append(
            "generated-artifacts.json: runtime type summary boundary_entry_hex must be exactly 16 bytes"
        )

    emitted_rows = summary.get("emitted_rows")
    named_rows = summary.get("named_definition_entries")
    if isinstance(emitted_rows, bool) or not isinstance(emitted_rows, int) or emitted_rows <= 0:
        errors.append(
            "generated-artifacts.json: runtime type summary emitted_rows must be a positive integer"
        )
    else:
        if named_rows != emitted_rows:
            errors.append(
                "generated-artifacts.json: runtime type summary named_definition_entries must equal emitted_rows"
            )
        if publication_rows is not None:
            published_rows = publication_rows.get("metadata/runtime-types.csv")
            if published_rows is not None and published_rows != emitted_rows:
                errors.append(
                    "generated-artifacts.json: runtime-types.csv publication row count disagrees with runtime summary"
                )

    if sample_hashes is not None:
        summary_exe = summary.get("exe_sha256")
        expected_exe = sample_hashes.get("exe_sha256")
        if not isinstance(summary_exe, str) or not HEX64.fullmatch(summary_exe):
            errors.append(
                "generated-artifacts.json: runtime type summary exe_sha256 must be a SHA-256"
            )
        elif expected_exe is not None and summary_exe.lower() != expected_exe.lower():
            errors.append(
                "generated-artifacts.json: runtime type summary EXE hash disagrees with publication provenance"
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
    expected_artifacts = set(CANONICAL_ARTIFACTS)
    if artifacts != expected_artifacts:
        missing = sorted(expected_artifacts - artifacts)
        extra = sorted(artifacts - expected_artifacts)
        errors.append(
            "generated-artifacts.json: artifacts must equal the canonical publication set; "
            f"missing={missing} extra={extra}"
        )

    if data.get("canonical_registry_published") is not True:
        errors.append(
            "generated-artifacts.json: canonical_registry_published must be true"
        )

    validation = data.get("validation")
    metadata_counts: dict[str, int] | None = None
    sample_hashes: dict[str, str] | None = None
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
        sample_hashes = _validate_sample_provenance(root, validation, errors)

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

    if isinstance(validation, dict):
        _validate_runtime_type_provenance(
            root,
            validation,
            publication_rows,
            sample_hashes,
            errors,
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
