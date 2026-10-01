from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

from .mhy71 import EXPECTED_EXE_SHA256, TYPE_ARRAY_POINTER_RVA
from .pe import PEImage

ENTRY_SIZE = 16
DEFAULT_MAX_ENTRIES = 1_000_000
ANCHOR_TYPE_INDEX = 405_772
ANCHOR_KIND = 0x12
ANCHOR_TYPE_DEFINITION = 84_249
ANCHOR_TYPE_NAME = "DMMJNICDOHM"

TYPE_KIND_NAMES = {
    0x01: "void",
    0x02: "boolean",
    0x03: "char",
    0x04: "i1",
    0x05: "u1",
    0x06: "i2",
    0x07: "u2",
    0x08: "i4",
    0x09: "u4",
    0x0A: "i8",
    0x0B: "u8",
    0x0C: "r4",
    0x0D: "r8",
    0x0E: "string",
    0x0F: "ptr",
    0x10: "byref",
    0x11: "valuetype",
    0x12: "class",
    0x13: "var",
    0x14: "array",
    0x15: "genericinst",
    0x16: "typedbyref",
    0x18: "i",
    0x19: "u",
    0x1B: "fnptr",
    0x1C: "object",
    0x1D: "szarray",
    0x1E: "mvar",
}

COLUMNS = (
    "type_index",
    "kind",
    "kind_name",
    "data_u32",
    "type_definition_index",
    "type_name",
    "entry_rva",
    "status",
    "evidence",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def decode_type_entry(entry: bytes) -> dict[str, int | str]:
    if len(entry) < ENTRY_SIZE:
        raise ValueError("truncated Il2CppType entry")
    data_u32 = int.from_bytes(entry[0:4], "little", signed=False)
    kind = entry[0x0A]
    return {
        "data_u32": data_u32,
        "kind": kind,
        "kind_name": TYPE_KIND_NAMES.get(kind, f"kind_0x{kind:02X}"),
    }


def _load_type_names(types_csv: Path) -> dict[int, str]:
    result: dict[int, str] = {}
    with types_csv.open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            try:
                index = int(str(row.get("type_definition_index", "")).strip())
            except ValueError:
                continue
            result[index] = str(row.get("type_name", ""))
    return result


def scan_type_array_71(
    exe: Path,
    types_csv: Path,
    output_csv: Path,
    summary_json: Path | None = None,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    include_all_kinds: bool = False,
    allow_unknown_sample: bool = False,
) -> dict[str, object]:
    exe_sha = _sha256(exe)
    if not allow_unknown_sample and exe_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"unexpected GenshinImpact.exe SHA-256: {exe_sha}")

    names = _load_type_names(types_csv)
    if not names:
        raise ValueError(f"no type definitions found in {types_csv}")

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    if summary_json is None:
        summary_json = output_csv.with_suffix(".summary.json")
    summary_json.parent.mkdir(parents=True, exist_ok=True)

    emitted = 0
    class_rows = 0
    value_type_rows = 0
    valid_named_rows = 0
    anchor_found = False
    kind_counts: dict[str, int] = {}
    pointer_neighborhood: dict[str, str] = {}

    with PEImage(exe) as image, output_csv.open("w", encoding="utf-8", newline="") as out:
        pointer_blob = image.read_rva(TYPE_ARRAY_POINTER_RVA, 8)
        if len(pointer_blob) != 8:
            raise ValueError("cannot read 7.1 IL2CPP type-array pointer")
        type_array_va = int.from_bytes(pointer_blob, "little", signed=False)
        type_array_rva = type_array_va - image.image_base
        if type_array_rva <= 0:
            raise ValueError("invalid 7.1 IL2CPP type-array pointer")

        for delta in range(-0x20, 0x29, 8):
            blob = image.read_rva(TYPE_ARRAY_POINTER_RVA + delta, 8)
            if len(blob) == 8:
                pointer_neighborhood[f"{delta:+#x}"] = f"0x{int.from_bytes(blob, 'little'):X}"

        section = next(
            (
                item
                for item in image.sections
                if item.virtual_address <= type_array_rva < item.virtual_address + max(item.virtual_size, item.raw_size)
            ),
            None,
        )
        if section is None:
            raise ValueError(f"type-array RVA 0x{type_array_rva:X} is outside PE sections")
        capacity = max(0, (section.virtual_address + section.raw_size - type_array_rva) // ENTRY_SIZE)
        scan_count = min(max_entries, capacity)
        blob = image.read_rva(type_array_rva, scan_count * ENTRY_SIZE)
        scan_count = len(blob) // ENTRY_SIZE

        writer = csv.DictWriter(out, fieldnames=COLUMNS)
        writer.writeheader()
        for index in range(scan_count):
            entry = blob[index * ENTRY_SIZE : (index + 1) * ENTRY_SIZE]
            decoded = decode_type_entry(entry)
            kind = int(decoded["kind"])
            kind_key = f"0x{kind:02X}"
            kind_counts[kind_key] = kind_counts.get(kind_key, 0) + 1

            is_definition_kind = kind in (0x11, 0x12)
            definition = int(decoded["data_u32"]) if is_definition_kind else None
            name = names.get(definition, "") if definition is not None else ""
            if is_definition_kind:
                if kind == 0x11:
                    value_type_rows += 1
                else:
                    class_rows += 1
                if name:
                    valid_named_rows += 1

            if (
                index == ANCHOR_TYPE_INDEX
                and kind == ANCHOR_KIND
                and definition == ANCHOR_TYPE_DEFINITION
                and name == ANCHOR_TYPE_NAME
            ):
                anchor_found = True

            if not include_all_kinds and not (is_definition_kind and name):
                continue

            writer.writerow(
                {
                    "type_index": index,
                    "kind": f"0x{kind:02X}",
                    "kind_name": decoded["kind_name"],
                    "data_u32": decoded["data_u32"],
                    "type_definition_index": "" if definition is None else definition,
                    "type_name": name,
                    "entry_rva": f"0x{type_array_rva + index * ENTRY_SIZE:X}",
                    "status": "static-decoded" if name else "candidate",
                    "evidence": "7.1 IL2CPP runtime type array",
                }
            )
            emitted += 1

    summary: dict[str, object] = {
        "exe": str(exe),
        "exe_sha256": exe_sha,
        "types_csv": str(types_csv),
        "type_array_pointer_source_rva": f"0x{TYPE_ARRAY_POINTER_RVA:X}",
        "type_array_va": f"0x{type_array_va:X}",
        "type_array_rva": f"0x{type_array_rva:X}",
        "pointer_source_neighborhood_qwords": pointer_neighborhood,
        "section": section.name,
        "section_capacity_entries": capacity,
        "scan_count": scan_count,
        "max_entries": max_entries,
        "include_all_kinds": include_all_kinds,
        "emitted_rows": emitted,
        "class_entries_seen": class_rows,
        "valuetype_entries_seen": value_type_rows,
        "named_definition_entries": valid_named_rows,
        "kind_counts": kind_counts,
        "anchor_405772_class_84249_DMMJNICDOHM": anchor_found,
        "status": "static-index",
        "notes": [
            "scan_count is bounded by --max-entries and the containing PE section, not a claimed runtime typesCount",
            "default CSV emits only class/valuetype entries that resolve to a decoded metadata type name",
            "the preserved 405772 -> typeDef 84249 anchor must pass before using this index for registry work",
        ],
    }
    summary_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.typearray",
        description="Export a queryable 7.1 IL2CPP runtime type-index map.",
    )
    parser.add_argument("exe", type=Path)
    parser.add_argument("types_csv", type=Path)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--max-entries", type=int, default=DEFAULT_MAX_ENTRIES)
    parser.add_argument("--all-kinds", action="store_true")
    parser.add_argument("--allow-unknown-sample", action="store_true")
    parser.add_argument("--require-anchor", action="store_true")
    args = parser.parse_args()

    result = scan_type_array_71(
        args.exe,
        args.types_csv,
        args.output_csv,
        summary_json=args.summary,
        max_entries=args.max_entries,
        include_all_kinds=args.all_kinds,
        allow_unknown_sample=args.allow_unknown_sample,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if args.require_anchor and not result["anchor_405772_class_84249_DMMJNICDOHM"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
