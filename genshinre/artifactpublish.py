from __future__ import annotations

import argparse
import csv
import json
import shutil
from pathlib import Path

from .mhy71 import (
    EXPECTED_FIELD_COUNT,
    EXPECTED_METHOD_COUNT,
    EXPECTED_TYPE_COUNT,
)
from .registrylayout import HISTORICAL_ROW_COUNT


CORE_FILES = {
    "metadata/types.csv": "metadata/types.csv",
    "metadata/fields.csv": "metadata/fields.csv",
    "metadata/methods.csv": "metadata/methods.csv",
    "metadata/method-pointers.csv": "metadata/method-pointers.csv",
    "metadata/type-methods.json": "metadata/type-methods.json",
    "metadata/native-decoder-summary.json": "metadata/native-decoder-summary.json",
    "metadata/runtime-types.csv": "metadata/runtime-types.csv",
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
    "known-opcodes.csv": "registry/known-opcodes.csv",
    "registry-candidate-graph.diagnostic.json": "registry/registry-candidate-graph.diagnostic.json",
    "registry-static-candidates.diagnostic.json": "registry/registry-static-candidates.diagnostic.json",
    "xrefs/message-handlers.csv": "xrefs/message-handlers.csv",
    "xrefs/message-senders.csv": "xrefs/message-senders.csv",
    "xrefs/message-constructors.csv": "xrefs/message-constructors.csv",
}

CANONICAL_FILES = {
    "registry.csv": "registry/registry.csv",
    "registry.json": "registry/registry.json",
    "summary.json": "registry/summary.json",
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


def _sample_hashes(version_dir: Path) -> tuple[str, str]:
    manifest = _load_json(version_dir / "hashes.json")
    samples = dict(manifest.get("samples", {}))
    exe_sha = str(dict(samples.get("GenshinImpact.exe", {})).get("sha256", ""))
    metadata_sha = str(dict(samples.get("global-metadata.dat", {})).get("sha256", ""))
    if not exe_sha or not metadata_sha:
        raise ValueError("version hashes.json is missing the exact sample hashes")
    return exe_sha, metadata_sha


def validate_generated_artifacts_71(
    work_dir: Path,
    version_dir: Path,
    expected_counts: tuple[int, int, int] = (
        EXPECTED_TYPE_COUNT,
        EXPECTED_FIELD_COUNT,
        EXPECTED_METHOD_COUNT,
    ),
) -> dict[str, object]:
    for source in CORE_FILES:
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

    type_methods = _load_json(work_dir / "metadata/type-methods.json")
    if not type_methods:
        raise ValueError("type-methods.json is empty")

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
    canonical_registry_dir: Path | None = None,
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

    copied = _copy_map(work_dir, version_dir, CORE_FILES)
    copied.extend(_copy_map(work_dir, version_dir, OPTIONAL_FILES))

    canonical_published = False
    if canonical_registry_dir is None:
        candidate = work_dir / "canonical-registry"
        canonical_registry_dir = candidate if candidate.is_dir() else None
    if canonical_registry_dir is not None:
        for source in CANONICAL_FILES:
            _require(canonical_registry_dir / source)
        canonical_summary = _load_json(canonical_registry_dir / "summary.json")
        if canonical_summary.get("status") != "canonical-static-registry":
            raise ValueError("canonical registry directory did not pass the publication gate")
        if int(canonical_summary.get("row_count", -1)) != HISTORICAL_ROW_COUNT:
            raise ValueError("canonical registry does not contain exactly 4,896 rows")
        if int(canonical_summary.get("unique_cmd_ids", -1)) != HISTORICAL_ROW_COUNT:
            raise ValueError("canonical registry does not contain 4,896 unique CmdIds")
        copied.extend(_copy_map(canonical_registry_dir, version_dir, CANONICAL_FILES))
        canonical_published = True

    published_files = sorted(copied)
    manifest: dict[str, object] = {
        "source": "genshinre.artifactpublish",
        "work": str(work_dir),
        "status": "generated-artifacts-published",
        "validation": validation,
        "canonical_registry_published": canonical_published,
        "files": published_files,
        # Compatibility alias for the repository-wide version validator while
        # older publication manifests are still present in Git history.
        "artifacts": published_files,
        "optional_registry_artifacts_published": [],
        "notes": [
            "metadata publication is gated independently from experimental registry heuristics",
            "the complete registry canonical filenames are emitted only by the stricter registry publication gate",
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
        description="Publish validated 7.1 generated research artifacts into the version directory.",
    )
    parser.add_argument("work_dir", type=Path)
    parser.add_argument("version_dir", type=Path)
    parser.add_argument("--canonical-registry", type=Path)
    args = parser.parse_args()

    result = publish_generated_artifacts_71(
        args.work_dir,
        args.version_dir,
        canonical_registry_dir=args.canonical_registry,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
