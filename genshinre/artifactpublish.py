from __future__ import annotations

import argparse
import csv
import json
import shutil
from pathlib import Path

from .metadata import build_type_methods
from .mhy71 import (
    EXPECTED_FIELD_COUNT,
    EXPECTED_METHOD_COUNT,
    EXPECTED_TYPE_COUNT,
)
from .registry import EXPECTED_REGISTRY_ROW_COUNT


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

OPTIONAL_FILES = {
    "metadata-usage-types.csv": "registry/metadata-usage-types.csv",
    "metadata-usage-types.summary.json": "registry/metadata-usage-types.summary.json",
    "registry-candidate-graph.csv": "registry/registry-candidate-graph.csv",
    "registry-candidate-graph.summary.json": "registry/registry-candidate-graph.summary.json",
    "registry-static-candidates.csv": "registry/registry-static-candidates.csv",
    "registry-static-candidates.summary.json": "registry/registry-static-candidates.summary.json",
    "control-set.csv": "registry/control-set.csv",
    "registry-candidate-graph.diagnostic.json": "registry/registry-candidate-graph.diagnostic.json",
    "registry-static-candidates.diagnostic.json": "registry/registry-static-candidates.diagnostic.json",
    "xrefs/message-handlers.csv": "xrefs/message-handlers.csv",
    "xrefs/message-senders.csv": "xrefs/message-senders.csv",
    "xrefs/message-constructors.csv": "xrefs/message-constructors.csv",
}


def _load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


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
                writer.writerow({column: row.get(column, "") for column in columns})
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


def _canonical_registry_published(version_dir: Path) -> bool:
    registry_csv = version_dir / "registry" / "registry.csv"
    summary_json = version_dir / "registry" / "registry.summary.json"
    if not registry_csv.exists() and not summary_json.exists():
        return False
    if not registry_csv.is_file() or not summary_json.is_file():
        raise ValueError(
            "canonical registry publication is incomplete: registry.csv and registry.summary.json must coexist"
        )

    summary = _load_json(summary_json)
    if summary.get("status") != "canonical-static-identity-registry":
        raise ValueError("registry.summary.json does not describe the current canonical identity registry")
    if int(summary.get("row_count", -1)) != EXPECTED_REGISTRY_ROW_COUNT:
        raise ValueError("canonical registry summary does not contain exactly 4,896 rows")
    if int(summary.get("unique_cmd_ids", -1)) != EXPECTED_REGISTRY_ROW_COUNT:
        raise ValueError("canonical registry summary does not contain 4,896 unique CmdIds")
    if not bool(summary.get("strict_slot_type_cmd_bijection")):
        raise ValueError("canonical registry summary lacks the strict slot/type/CmdId bijection gate")
    if _csv_row_count(registry_csv) != EXPECTED_REGISTRY_ROW_COUNT:
        raise ValueError("canonical registry CSV does not contain exactly 4,896 rows")
    return True


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
    if str(runtime.get("exe_sha256", "")) != expected_exe_sha:
        raise ValueError("runtime type index EXE hash does not match the version manifest")
    if not bool(runtime.get("anchor_405772_class_84249_DMMJNICDOHM")):
        raise ValueError("runtime type index failed the preserved 405772 -> DMMJNICDOHM anchor")

    getcmd = _load_json(work_dir / "getcmdid-candidates.summary.json")
    if str(getcmd.get("exe_sha256", "")) != expected_exe_sha:
        raise ValueError("GetCmdId candidate scan EXE hash does not match the version manifest")
    if not bool(getcmd.get("anchor_26105_HJDNCHODGOL_0x10587260")):
        raise ValueError("GetCmdId candidate scan failed the preserved 26105 anchor")
    if int(getcmd.get("method_rows", -1)) != expected_methods:
        raise ValueError("GetCmdId scan did not consume the complete decoded methods table")

    optional_checks: dict[str, object] = {}
    usage_summary = work_dir / "metadata-usage-types.summary.json"
    if usage_summary.is_file():
        usage = _load_json(usage_summary)
        optional_checks["usage_type_anchor"] = bool(
            usage.get("anchor_37523_to_405772_to_84249_DMMJNICDOHM")
        )

    graph_summary = work_dir / "registry-candidate-graph.summary.json"
    if graph_summary.is_file():
        graph = _load_json(graph_summary)
        optional_checks["registry_graph_anchors"] = bool(
            graph.get("all_preserved_anchors_pass")
        )

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
        "getcmdid_anchor": True,
        "optional_registry_checks": optional_checks,
    }


def _copy_map(source_root: Path, destination_root: Path, mapping: dict[str, str]) -> list[str]:
    copied: list[str] = []
    for source_rel, destination_rel in mapping.items():
        source = source_root / source_rel
        if not source.is_file():
            continue
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

    direct_files = _copy_map(work_dir, version_dir, DIRECT_FILES)
    optional_files = _copy_map(work_dir, version_dir, OPTIONAL_FILES)
    published_files.extend(direct_files)
    published_files.extend(optional_files)
    canonical_published = _canonical_registry_published(version_dir)

    published_files = sorted(set(published_files))
    optional_files = sorted(set(optional_files))
    manifest: dict[str, object] = {
        "manifest_version": 2,
        "source": "genshinre.artifactpublish",
        "work": str(work_dir),
        "status": "generated-artifacts-published",
        "validation": validation,
        "publication": {
            "metadata_format": "compact-query-indexes",
            "metadata_rows": compact_counts,
        },
        "canonical_registry_published": canonical_published,
        "artifacts": published_files,
        "optional_artifacts_published": optional_files,
        "notes": [
            "native decoder work files retain full provenance columns; canonical metadata CSVs publish the query-relevant compact projection",
            "metadata publication is gated independently from experimental registry heuristics",
            "the existing canonical registry is validated and preserved; this publisher does not replace it",
            "intermediate registry artifacts remain evidence/candidate datasets and must not be treated as canonical mappings",
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
        description="Publish validated compact 7.1 research artifacts into the version directory.",
    )
    parser.add_argument("work_dir", type=Path)
    parser.add_argument("version_dir", type=Path)
    args = parser.parse_args()

    result = publish_generated_artifacts_71(args.work_dir, args.version_dir)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
