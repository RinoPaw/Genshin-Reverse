from __future__ import annotations

import argparse
import csv
import json
import shutil
from pathlib import Path

from .artifactmanifest import CANONICAL_ARTIFACTS
from .metadata import build_type_methods
from .nativeprofile import PROFILE_71
from .registry import CANONICAL_REGISTRY_COLUMNS, EXPECTED_REGISTRY_ROW_COUNT
from .typearray import ENTRY_SIZE

EXPECTED_TYPE_COUNT = PROFILE_71.type_definition_count
EXPECTED_FIELD_COUNT = PROFILE_71.field_count
EXPECTED_METHOD_COUNT = PROFILE_71.method_count
EXPECTED_RUNTIME_TYPE_COUNT = PROFILE_71.runtime_type_count


REQUIRED_WORK_FILES = (
    "metadata/types.csv",
    "metadata/fields.csv",
    "metadata/methods.csv",
    "metadata/method-pointers.csv",
    "metadata/native-decoder-summary.json",
    "metadata/runtime-types.csv",
    "metadata/runtime-types.summary.json",
    "getcmdid-candidates.csv",
    "getcmdid-candidates.summary.json",
)

COMPACT_METADATA = {
    "metadata/types.csv": (
        "type_definition_index",
        "namespace",
        "type_name",
        "parent_type",
        "field_start",
        "field_count",
        "method_start",
        "method_count",
        "name_token",
        "record_file_offset",
    ),
    "metadata/fields.csv": (
        "field_index",
        "type_definition_index",
        "type_name",
        "field_name",
        "field_type",
        "field_type_index",
        "name_token",
        "offset",
        "record_file_offset",
    ),
    "metadata/methods.csv": (
        "method_index",
        "type_definition_index",
        "type_name",
        "method_name",
        "rva",
        "return_type",
        "parameter_types",
        "parameter_start",
        "parameter_count",
        "name_token",
    ),
    "metadata/method-pointers.csv": (
        "method_index",
        "rva",
        "va",
    ),
    "metadata/runtime-types.csv": (
        "type_index",
        "kind",
        "kind_name",
        "data_u32",
        "type_definition_index",
        "type_name",
        "entry_rva",
    ),
}

DIRECT_FILES = {
    "metadata/native-decoder-summary.json": "metadata/native-decoder-summary.json",
    "metadata/runtime-types.summary.json": "metadata/runtime-types.summary.json",
    "getcmdid-candidates.csv": "registry/getcmdid-candidates.csv",
    "getcmdid-candidates.summary.json": "registry/getcmdid-candidates.summary.json",
}

EXPECTED_RUNTIME_STATUS = "canonical-exact-runtime-type-index"


def _load_json(path: Path) -> dict[str, object]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError(f"expected JSON object: {path}")
    return data


def _csv_row_count(path: Path) -> int:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.reader(f)
        try:
            next(reader)
        except StopIteration:
            return 0
        return sum(1 for _ in reader)


def _require(path: Path) -> None:
    if not path.is_file():
        raise ValueError(f"required generated artifact is missing: {path}")


def _compact_csv(source: Path, destination: Path, columns: tuple[str, ...]) -> int:
    _require(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("r", encoding="utf-8-sig", newline="") as src:
        reader = csv.DictReader(src)
        available = set(reader.fieldnames or ())
        missing = [column for column in columns if column not in available]
        if missing:
            raise ValueError(
                f"{source} missing canonical publication columns: {', '.join(missing)}"
            )
        with destination.open("w", encoding="utf-8", newline="") as dst:
            writer = csv.DictWriter(dst, fieldnames=columns)
            writer.writeheader()
            count = 0
            for row in reader:
                writer.writerow({column: row[column] for column in columns})
                count += 1
    return count


def _sample_hashes(version_dir: Path) -> tuple[str, str]:
    manifest = _load_json(version_dir / "hashes.json")
    samples = dict(manifest.get("samples", {}))
    exe_sha = str(dict(samples.get("GenshinImpact.exe", {})).get("sha256", ""))
    metadata_sha = str(dict(samples.get("global-metadata.dat", {})).get("sha256", ""))
    if not exe_sha or not metadata_sha:
        raise ValueError("version hashes.json is missing the exact sample hashes")
    return exe_sha, metadata_sha


def _parse_hex_rva(value: object, label: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError(f"{label} must be a hexadecimal RVA")
    try:
        return int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{label} must be a hexadecimal RVA") from exc


def _require_canonical_registry(version_dir: Path) -> None:
    registry_csv = version_dir / "registry" / "registry.csv"
    summary_json = version_dir / "registry" / "registry.summary.json"
    if not registry_csv.is_file() or not summary_json.is_file():
        raise ValueError(
            "current canonical registry is required: registry.csv and registry.summary.json must coexist"
        )

    summary = _load_json(summary_json)
    if summary.get("status") != "canonical-static-identity-registry":
        raise ValueError("registry.summary.json does not describe the current canonical identity registry")
    if int(summary.get("row_count", -1)) != EXPECTED_REGISTRY_ROW_COUNT:
        raise ValueError("canonical registry summary does not contain exactly 4,896 rows")
    if int(summary.get("unique_cmd_ids", -1)) != EXPECTED_REGISTRY_ROW_COUNT:
        raise ValueError("canonical registry summary does not contain 4,896 unique CmdIds")
    if summary.get("strict_slot_type_cmd_bijection") is not True:
        raise ValueError("canonical registry summary lacks the strict slot/type/CmdId bijection gate")

    with registry_csv.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fields = tuple(reader.fieldnames or ())
        if fields != CANONICAL_REGISTRY_COLUMNS:
            raise ValueError(
                "canonical registry CSV header mismatch: "
                f"expected {','.join(CANONICAL_REGISTRY_COLUMNS)}; got {','.join(fields)}"
            )
        rows = list(reader)

    if len(rows) != EXPECTED_REGISTRY_ROW_COUNT:
        raise ValueError("canonical registry CSV does not contain exactly 4,896 rows")
    try:
        cmd_ids = [int(row["cmd_id"]) for row in rows]
    except (KeyError, ValueError) as exc:
        raise ValueError("canonical registry CSV contains an invalid CmdId") from exc
    if len(set(cmd_ids)) != EXPECTED_REGISTRY_ROW_COUNT:
        raise ValueError("canonical registry CSV does not contain 4,896 unique CmdIds")


def _validate_runtime_type_summary(
    runtime: dict[str, object],
    runtime_csv_rows: int,
    expected_exe_sha: str,
) -> tuple[int, str]:
    if str(runtime.get("exe_sha256", "")) != expected_exe_sha:
        raise ValueError("runtime type index EXE hash does not match the version manifest")
    if runtime.get("status") != EXPECTED_RUNTIME_STATUS:
        raise ValueError(
            f"runtime type index status must be {EXPECTED_RUNTIME_STATUS}"
        )
    if runtime.get("anchor_405772_class_84249_DMMJNICDOHM") is not True:
        raise ValueError("runtime type index failed the preserved 405772 -> DMMJNICDOHM anchor")
    if runtime.get("structural_validation_passed") is not True:
        raise ValueError("runtime type index did not pass complete structural validation")
    if runtime.get("boundary_entry_valid_type") is not False:
        raise ValueError("runtime type boundary entry must fail the Il2CppType structural gate")

    count = runtime.get("runtime_type_count")
    if isinstance(count, bool) or not isinstance(count, int):
        raise ValueError("runtime type index is missing an integer runtime_type_count")
    if count != EXPECTED_RUNTIME_TYPE_COUNT:
        raise ValueError(
            f"runtime type count {count} != preserved {EXPECTED_RUNTIME_TYPE_COUNT}"
        )

    type_array_rva = _parse_hex_rva(runtime.get("type_array_rva"), "runtime type_array_rva")
    boundary_rva = _parse_hex_rva(runtime.get("boundary_rva"), "runtime boundary_rva")
    expected_boundary = type_array_rva + count * ENTRY_SIZE
    if boundary_rva != expected_boundary:
        raise ValueError(
            "runtime type boundary does not equal type_array_rva + runtime_type_count * 16"
        )

    boundary_hex = runtime.get("boundary_entry_hex")
    if not isinstance(boundary_hex, str) or len(boundary_hex) != ENTRY_SIZE * 2:
        raise ValueError("runtime type boundary entry must contain exactly 16 bytes")
    try:
        bytes.fromhex(boundary_hex)
    except ValueError as exc:
        raise ValueError("runtime type boundary entry is not valid hex") from exc

    emitted_rows = runtime.get("emitted_rows")
    named_rows = runtime.get("named_definition_entries")
    if isinstance(emitted_rows, bool) or not isinstance(emitted_rows, int) or emitted_rows <= 0:
        raise ValueError("runtime type summary emitted_rows must be a positive integer")
    if named_rows != emitted_rows:
        raise ValueError("runtime type summary named_definition_entries must equal emitted_rows")
    if runtime_csv_rows != emitted_rows:
        raise ValueError(
            "runtime type CSV row count does not match the exact-boundary runtime summary"
        )

    return count, f"0x{boundary_rva:X}"


def validate_generated_artifacts_71(
    work_dir: Path,
    version_dir: Path,
    expected_counts: tuple[int, int, int] = (
        EXPECTED_TYPE_COUNT,
        EXPECTED_FIELD_COUNT,
        EXPECTED_METHOD_COUNT,
    ),
) -> dict[str, object]:
    for source in REQUIRED_WORK_FILES:
        _require(work_dir / source)
    _require(version_dir / "hashes.json")
    _require_canonical_registry(version_dir)

    _, _, expected_methods = expected_counts
    native = _load_json(work_dir / "metadata/native-decoder-summary.json")
    counts = dict(native.get("counts", {}))
    actual_summary_counts = (
        int(counts.get("types", -1)),
        int(counts.get("fields", -1)),
        int(counts.get("methods", -1)),
    )
    if actual_summary_counts != expected_counts:
        raise ValueError(
            "native metadata summary count mismatch: "
            f"{actual_summary_counts} != {expected_counts}"
        )

    actual_csv_counts = (
        _csv_row_count(work_dir / "metadata/types.csv"),
        _csv_row_count(work_dir / "metadata/fields.csv"),
        _csv_row_count(work_dir / "metadata/methods.csv"),
    )
    if actual_csv_counts != expected_counts:
        raise ValueError(
            "generated metadata CSV row count mismatch: "
            f"{actual_csv_counts} != {expected_counts}"
        )

    method_pointer_count = _csv_row_count(work_dir / "metadata/method-pointers.csv")
    if method_pointer_count != expected_methods:
        raise ValueError(
            "generated method-pointer CSV row count mismatch: "
            f"{method_pointer_count} != {expected_methods}"
        )

    expected_exe_sha, expected_metadata_sha = _sample_hashes(version_dir)
    sample = dict(native.get("sample", {}))
    if str(sample.get("exe_sha256", "")) != expected_exe_sha:
        raise ValueError("native decoder EXE hash does not match the version manifest")
    if str(sample.get("metadata_sha256", "")) != expected_metadata_sha:
        raise ValueError("native decoder metadata hash does not match the version manifest")

    runtime = _load_json(work_dir / "metadata/runtime-types.summary.json")
    runtime_csv_rows = _csv_row_count(work_dir / "metadata/runtime-types.csv")
    runtime_type_count, runtime_boundary_rva = _validate_runtime_type_summary(
        runtime,
        runtime_csv_rows,
        expected_exe_sha,
    )

    getcmd = _load_json(work_dir / "getcmdid-candidates.summary.json")
    if str(getcmd.get("exe_sha256", "")) != expected_exe_sha:
        raise ValueError("GetCmdId candidate scan EXE hash does not match the version manifest")
    if getcmd.get("anchor_26105_HJDNCHODGOL_0x10587260") is not True:
        raise ValueError("GetCmdId candidate scan failed the preserved 26105 anchor")
    if int(getcmd.get("method_rows", -1)) != expected_methods:
        raise ValueError("GetCmdId scan did not consume the complete decoded methods table")

    return {
        "metadata_counts": {
            "types": actual_csv_counts[0],
            "fields": actual_csv_counts[1],
            "methods": actual_csv_counts[2],
            "method_pointers": method_pointer_count,
        },
        "sample": {
            "exe_sha256": expected_exe_sha,
            "metadata_sha256": expected_metadata_sha,
        },
        "runtime_type_anchor": True,
        "runtime_type_count": runtime_type_count,
        "runtime_type_boundary_rva": runtime_boundary_rva,
        "runtime_type_boundary_verified": True,
        "getcmdid_anchor": True,
    }


def _copy_required_files(source_root: Path, destination_root: Path) -> list[str]:
    copied: list[str] = []
    for source_rel, destination_rel in DIRECT_FILES.items():
        source = source_root / source_rel
        _require(source)
        destination = destination_root / destination_rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        copied.append(destination_rel)
    return copied


def publish_generated_artifacts_71(
    work_dir: Path,
    version_dir: Path,
    expected_counts: tuple[int, int, int] = (
        EXPECTED_TYPE_COUNT,
        EXPECTED_FIELD_COUNT,
        EXPECTED_METHOD_COUNT,
    ),
) -> dict[str, object]:
    validation = validate_generated_artifacts_71(
        work_dir,
        version_dir,
        expected_counts=expected_counts,
    )
    runtime = _load_json(work_dir / "metadata/runtime-types.summary.json")
    runtime_rows = int(runtime["emitted_rows"])

    published_files: list[str] = []
    compact_counts: dict[str, int] = {}
    for rel, columns in COMPACT_METADATA.items():
        count = _compact_csv(work_dir / rel, version_dir / rel, columns)
        compact_counts[rel] = count
        published_files.append(rel)

    expected_by_rel = {
        "metadata/types.csv": expected_counts[0],
        "metadata/fields.csv": expected_counts[1],
        "metadata/methods.csv": expected_counts[2],
        "metadata/method-pointers.csv": expected_counts[2],
        "metadata/runtime-types.csv": runtime_rows,
    }
    for rel, expected in expected_by_rel.items():
        if compact_counts[rel] != expected:
            raise ValueError(
                f"canonical compact publication row count mismatch for {rel}: "
                f"{compact_counts[rel]} != {expected}"
            )

    type_methods_path = version_dir / "metadata/type-methods.json"
    build_type_methods(version_dir / "metadata/methods.csv", type_methods_path)
    published_files.append("metadata/type-methods.json")
    published_files.extend(_copy_required_files(work_dir, version_dir))
    published_files = sorted(set(published_files))
    if tuple(published_files) != CANONICAL_ARTIFACTS:
        raise RuntimeError(
            "canonical publisher artifact set drift: "
            f"expected {CANONICAL_ARTIFACTS}; got {tuple(published_files)}"
        )

    manifest: dict[str, object] = {
        "manifest_version": 4,
        "source": "genshinre.artifactpublish",
        "work": str(work_dir),
        "status": "generated-artifacts-published",
        "validation": validation,
        "publication": {
            "metadata_format": "compact-query-indexes",
            "metadata_rows": compact_counts,
        },
        "canonical_registry_published": True,
        "artifacts": published_files,
        "notes": [
            "native decoder work files retain full provenance columns; canonical metadata CSVs publish the query-relevant compact projection",
            "publication requires the current canonical 7.1 registry and exact sample identities",
            "runtime type publication is bound to the verified exact 683,574-entry Il2CppType boundary",
            "research intermediates are maintained by their own explicit research workflows",
        ],
    }
    (version_dir / "generated-artifacts.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.artifactpublish",
        description="Publish validated canonical 7.1 artifacts into the version directory.",
    )
    parser.add_argument("work_dir", type=Path)
    parser.add_argument("version_dir", type=Path)
    args = parser.parse_args()

    result = publish_generated_artifacts_71(args.work_dir, args.version_dir)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
