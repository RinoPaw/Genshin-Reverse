from __future__ import annotations

import argparse
import csv
import json
import mmap
from pathlib import Path

from genshinre.mhy71 import (
    BODY_SKIP,
    EMBEDDED_HEADER_RVA,
    EMBEDDED_HEADER_SIZE,
    _header_layout,
)
from genshinre.param71 import PARAMETER_RECORD_SIZE, decode_parameter_record
from genshinre.pe import PEImage

ANCHORS = {
    0x0C227790: "ONKOPMILDMF",
    0x0C23BA20: "PGAMFBPNNIC",
    0x0C2513A0: "OBOADLPIEPL",
}


def load_runtime_types(path: Path) -> dict[int, str]:
    result: dict[int, str] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            try:
                index = int(row["type_index"], 0)
            except (KeyError, ValueError):
                continue
            result[index] = row.get("type_name", "") or row.get("kind_name", "") or f"type_index:{index}"
    return result


def parse_int(value: str | None, default: int = 0) -> int:
    text = (value or "").strip()
    if not text:
        return default
    return int(text, 0)


def main() -> None:
    p = argparse.ArgumentParser(description="Decode exact 7.1 MHY method parameter types into methods.csv form.")
    p.add_argument("exe", type=Path)
    p.add_argument("metadata", type=Path)
    p.add_argument("methods_csv", type=Path)
    p.add_argument("runtime_types_csv", type=Path)
    p.add_argument("output_csv", type=Path)
    p.add_argument("--summary", type=Path)
    args = p.parse_args()

    runtime_types = load_runtime_types(args.runtime_types_csv)
    if not runtime_types:
        raise SystemExit("runtime type map is empty")

    with PEImage(args.exe) as image:
        header = image.read_rva(EMBEDDED_HEADER_RVA, EMBEDDED_HEADER_SIZE)
        layout = _header_layout(header)
    parameter_base = BODY_SKIP + int(layout["parameter_offset"])

    with args.methods_csv.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fieldnames = list(reader.fieldnames or [])
    if "parameter_types" not in fieldnames:
        raise SystemExit("methods CSV has no parameter_types column")

    decoded_parameter_count = 0
    unresolved_type_indices: dict[int, int] = {}
    anchor_results: dict[str, object] = {}

    args.output_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.metadata.open("rb") as metadata_file:
        metadata = mmap.mmap(metadata_file.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            for row in rows:
                start = parse_int(row.get("parameter_start"), -1)
                count = parse_int(row.get("parameter_count"), 0)
                params: list[str] = []
                param_type_indices: list[int] = []
                if start >= 0 and count > 0:
                    if count > 255:
                        raise ValueError(f"implausible parameter count {count} for method {row.get('method_index')}")
                    for ordinal in range(count):
                        index = start + ordinal
                        offset = parameter_base + index * PARAMETER_RECORD_SIZE
                        end = offset + PARAMETER_RECORD_SIZE
                        if offset < 0 or end > len(metadata):
                            raise ValueError(f"parameter record {index} exceeds metadata")
                        decoded = decode_parameter_record(metadata[offset:end], index)
                        type_index = int(decoded["type_index"])
                        param_type_indices.append(type_index)
                        type_name = runtime_types.get(type_index)
                        if not type_name:
                            unresolved_type_indices[type_index] = unresolved_type_indices.get(type_index, 0) + 1
                            type_name = f"type_index:{type_index}"
                        params.append(type_name)
                        decoded_parameter_count += 1
                row["parameter_types"] = json.dumps(params, ensure_ascii=False)

                method_rva = parse_int(row.get("rva"), 0)
                expected = ANCHORS.get(method_rva)
                if expected is not None:
                    matched = bool(params) and params[0] == expected
                    anchor_results[f"0x{method_rva:X}"] = {
                        "expected_first_parameter": expected,
                        "decoded_parameters": params,
                        "decoded_type_indices": param_type_indices,
                        "matched": matched,
                    }

            missing_anchors = [f"0x{rva:X}" for rva in ANCHORS if f"0x{rva:X}" not in anchor_results]
            mismatched_anchors = [rva for rva, item in anchor_results.items() if not bool(item["matched"])]
            if missing_anchors or mismatched_anchors:
                raise ValueError(
                    f"parameter decoder anchor validation failed: missing={missing_anchors}, mismatched={mismatched_anchors}"
                )

            with args.output_csv.open("w", encoding="utf-8", newline="") as out:
                writer = csv.DictWriter(out, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
        finally:
            metadata.close()

    summary = {
        "method_count": len(rows),
        "decoded_parameter_count": decoded_parameter_count,
        "parameter_record_size": PARAMETER_RECORD_SIZE,
        "parameter_base_file_offset": f"0x{parameter_base:X}",
        "resolved_runtime_type_count": len(runtime_types),
        "unresolved_type_index_count": len(unresolved_type_indices),
        "unresolved_type_occurrences": sum(unresolved_type_indices.values()),
        "unresolved_type_examples": [
            {"type_index": index, "occurrences": count}
            for index, count in sorted(unresolved_type_indices.items(), key=lambda item: item[1], reverse=True)[:30]
        ],
        "anchors": anchor_results,
        "status": "static-decoded-current-7.1",
        "evidence": (
            "exact-client native decoder loop at RVA 0x52881C..0x528867; "
            "validated against three independent confirmed handler parameter anchors"
        ),
    }
    summary_path = args.summary or args.output_csv.with_suffix(".summary.json")
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
