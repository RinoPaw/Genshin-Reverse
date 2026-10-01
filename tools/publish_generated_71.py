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


def compact_csv(src: Path, dst: Path, keep: tuple[str, ...]) -> int:
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
    output_json.write_text(json.dumps({"by_type_name": by_name, "by_type_definition_index": by_index}, separators=(",", ":"), ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Publish computation-friendly 7.1 derived artifacts from a regeneration work directory.")
    parser.add_argument("work", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    work, dest = args.work, args.destination

    registry = dest / "registry"
    metadata = dest / "metadata"

    for name in ("registry-candidate-graph.csv", "metadata-usage-types.csv", "getcmdid-candidates.csv"):
        copy_required(work / name, registry / name)

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
        work / "metadata" / "methods.csv",
        metadata / "methods.csv",
        ("method_index", "type_definition_index", "type_name", "method_name", "rva", "return_type", "parameter_types", "parameter_start", "parameter_count", "name_token"),
    )
    build_type_methods(metadata / "methods.csv", metadata / "type-methods.json")

    canonical = work / "canonical-registry"
    if (canonical / "registry.csv").exists():
        for name in ("registry.csv", "registry.json", "summary.json"):
            if (canonical / name).exists():
                copy_required(canonical / name, registry / name)

    manifest = {
        "source": "tools/publish_generated_71.py",
        "work": str(work),
        "canonical_registry_published": (registry / "registry.csv").exists(),
        "artifacts": [str(path.relative_to(dest)) for path in sorted(dest.rglob("*")) if path.is_file()],
    }
    (dest / "generated-artifacts.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
