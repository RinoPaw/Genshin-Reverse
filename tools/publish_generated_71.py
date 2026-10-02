#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import shutil
from collections import defaultdict
from pathlib import Path


def copy_required(src: Path, dst: Path) -> None:
    if not src.exists():
        raise FileNotFoundError(src)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)


def copy_optional(src: Path, dst: Path) -> bool:
    if not src.exists():
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    return True


def compact_csv(src: Path, dst: Path, keep: tuple[str, ...]) -> int:
    if not src.exists():
        raise FileNotFoundError(src)
    dst.parent.mkdir(parents=True, exist_ok=True)
    with src.open("r", encoding="utf-8-sig", newline="") as inp, dst.open("w", encoding="utf-8", newline="") as out:
        reader = csv.DictReader(inp)
        if reader.fieldnames is None:
            raise ValueError(f"{src} has no CSV header")
        fields = [name for name in keep if name in reader.fieldnames]
        writer = csv.DictWriter(out, fieldnames=fields)
        writer.writeheader()
        count = 0
        for row in reader:
            writer.writerow({name: row.get(name, "") for name in fields})
            count += 1
    return count


def build_type_methods(methods_csv: Path, output_json: Path) -> None:
    by_name: dict[str, list[int]] = defaultdict(list)
    by_index: dict[str, list[int]] = defaultdict(list)
    with methods_csv.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            try:
                method_index = int(str(row.get("method_index", "")))
            except ValueError:
                continue
            name = str(row.get("type_name", "")).strip()
            index = str(row.get("type_definition_index", "")).strip()
            if name:
                by_name[name].append(method_index)
            if index:
                by_index[index].append(method_index)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(
        json.dumps(
            {"by_type_name": by_name, "by_type_definition_index": by_index},
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Publish computation-friendly 7.1 derived artifacts from a regeneration work directory.")
    parser.add_argument("work", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    work, dest = args.work, args.destination

    registry = dest / "registry"
    metadata = dest / "metadata"

    # These metadata artifacts are independently useful and are required once the
    # native metadata decoder has succeeded. Do not let a later registry-recovery
    # experiment prevent them from being published.
    compact_csv(
        work / "metadata" / "runtime-types.csv",
        metadata / "runtime-types.csv",
        ("type_index", "kind", "kind_name", "data_u32", "type_definition_index", "type_name", "entry_rva"),
    )
    compact_csv(
        work / "metadata" / "types.csv",
        metadata / "types.csv",
        ("type_definition_index", "namespace", "type_name", "parent_type", "field_start", "field_count", "method_start", "method_count", "name_token", "record_file_offset"),
    )
    compact_csv(
        work / "metadata" / "fields.csv",
        metadata / "fields.csv",
        ("field_index", "type_definition_index", "type_name", "field_name", "field_type", "field_type_index", "name_token", "offset", "record_file_offset"),
    )
    compact_csv(
        work / "metadata" / "methods.csv",
        metadata / "methods.csv",
        ("method_index", "type_definition_index", "type_name", "method_name", "rva", "return_type", "parameter_types", "parameter_start", "parameter_count", "name_token"),
    )
    compact_csv(
        work / "metadata" / "method-pointers.csv",
        metadata / "method-pointers.csv",
        ("method_index", "rva", "va"),
    )
    build_type_methods(metadata / "methods.csv", metadata / "type-methods.json")

    # Keep every registry-side artifact that actually exists. Several recovery
    # paths are intentionally independent; a failed usage-table experiment must
    # not hide GetCmdId candidates or a native-layout result from researchers.
    optional_registry = (
        "getcmdid-candidates.csv",
        "getcmdid-candidates.summary.json",
        "metadata-usage-types.csv",
        "metadata-usage-types.summary.json",
        "registry-candidate-graph.csv",
        "registry-candidate-graph.summary.json",
        "registry-static-candidates.csv",
        "registry-static-candidates.summary.json",
        "registry-native-direct.csv",
        "registry-native-direct.summary.json",
        "registry-native-usage.csv",
        "registry-native-usage.summary.json",
        "registry-native-compare.json",
        "registry-direction-audit.json",
        "registry-type-slots.csv",
        "registry-type-slots.summary.json",
        "registry-layout-probe.json",
        "registry-usage-layout-probe.json",
        "metadata-usage-slots.csv",
        "metadata-usage-slots.summary.json",
        "metadata-registration-probe.json",
    )
    copied_optional = []
    for name in optional_registry:
        if copy_optional(work / name, registry / name):
            copied_optional.append(name)

    canonical = work / "canonical-registry"
    if (canonical / "registry.csv").exists():
        for name in ("registry.csv", "registry.json", "summary.json"):
            if (canonical / name).exists():
                copy_required(canonical / name, registry / name)

    manifest = {
        "source": "tools/publish_generated_71.py",
        "work": str(work),
        "canonical_registry_published": (registry / "registry.csv").exists(),
        "optional_registry_artifacts_published": copied_optional,
        "artifacts": [str(path.relative_to(dest)) for path in sorted(dest.rglob("*")) if path.is_file()],
    }
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "generated-artifacts.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
