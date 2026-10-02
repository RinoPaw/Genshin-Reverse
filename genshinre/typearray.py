from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

from .mhy71 import EXPECTED_EXE_SHA256, EXPECTED_TYPE_COUNT, TYPE_ARRAY_POINTER_RVA
from .pe import PEImage

ENTRY_SIZE = 16
EXPECTED_RUNTIME_TYPE_COUNT = 683_574
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
    0x1F: "cmod_reqd",
    0x20: "cmod_opt",
    0x21: "internal",
    0x40: "modifier",
    0x41: "sentinel",
    0x45: "pinned",
    0x55: "enum",
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
    if len(entry) != ENTRY_SIZE:
        raise ValueError("Il2CppType entry must be exactly 16 bytes")
    data_u32 = int.from_bytes(entry[0:4], "little", signed=False)
    kind = entry[0x0A]
    return {
        "data_u32": data_u32,
        "kind": kind,
        "kind_name": TYPE_KIND_NAMES.get(kind, f"kind_0x{kind:02X}"),
    }


def is_valid_type_entry(entry: bytes, *, type_definition_count: int = EXPECTED_TYPE_COUNT) -> bool:
    if len(entry) != ENTRY_SIZE:
        return False
    kind = entry[0x0A]
    if kind not in TYPE_KIND_NAMES:
        return False
    if entry[0x0C:0x10] != b"\0" * 4:
        return False
    if kind in (0x11, 0x12):
        data_u64 = int.from_bytes(entry[0:8], "little", signed=False)
        if data_u64 >> 32:
            return False
        if (data_u64 & 0xFFFFFFFF) >= type_definition_count:
            return False
    return True


def _load_type_names(types_csv: Path) -> dict[int, str]:
    result: dict[int, str] = {}
    with types_csv.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fields = set(reader.fieldnames or ())
        missing = {"type_definition_index", "type_name"} - fields
        if missing:
            raise ValueError(
                f"{types_csv} missing required columns: {', '.join(sorted(missing))}"
            )
        for line_no, row in enumerate(reader, start=2):
            text = str(row["type_definition_index"]).strip()
            if not text:
                raise ValueError(f"{types_csv}:{line_no}: missing type_definition_index")
            try:
                index = int(text, 0)
            except ValueError as exc:
                raise ValueError(
                    f"{types_csv}:{line_no}: bad type_definition_index {text!r}"
                ) from exc
            if index in result:
                raise ValueError(
                    f"{types_csv}:{line_no}: duplicate type_definition_index {index}"
                )
            result[index] = str(row["type_name"])
    return result


def scan_type_array_71(
    exe: Path,
    types_csv: Path,
    output_csv: Path,
    summary_json: Path | None = None,
    include_all_kinds: bool = False,
) -> dict[str, object]:
    exe_sha = _sha256(exe)
    if exe_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"unexpected GenshinImpact.exe SHA-256: {exe_sha}")

    names = _load_type_names(types_csv)
    if len(names) != EXPECTED_TYPE_COUNT:
        raise ValueError(
            f"decoded metadata type count {len(names)} != preserved {EXPECTED_TYPE_COUNT}"
        )

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
            data = image.read_rva(TYPE_ARRAY_POINTER_RVA + delta, 8)
            if len(data) != 8:
                raise ValueError(
                    f"cannot read type-array pointer neighborhood at delta {delta:+#x}"
                )
            pointer_neighborhood[f"{delta:+#x}"] = f"0x{int.from_bytes(data, 'little'):X}"

        section = next(
            (
                item
                for item in image.sections
                if item.virtual_address
                <= type_array_rva
                < item.virtual_address + max(item.virtual_size, item.raw_size)
            ),
            None,
        )
        if section is None:
            raise ValueError(f"type-array RVA 0x{type_array_rva:X} is outside PE sections")
        capacity = max(
            0,
            (section.virtual_address + section.raw_size - type_array_rva) // ENTRY_SIZE,
        )
        if capacity <= EXPECTED_RUNTIME_TYPE_COUNT:
            raise ValueError(
                "containing PE section does not include the verified runtime type boundary"
            )

        read_count = EXPECTED_RUNTIME_TYPE_COUNT + 1
        expected_bytes = read_count * ENTRY_SIZE
        blob = image.read_rva(type_array_rva, expected_bytes)
        if len(blob) != expected_bytes:
            raise ValueError(
                "runtime type-array boundary read was truncated: "
                f"expected {expected_bytes} bytes, got {len(blob)}"
            )

        writer = csv.DictWriter(out, fieldnames=COLUMNS)
        writer.writeheader()
        for index in range(EXPECTED_RUNTIME_TYPE_COUNT):
            entry = blob[index * ENTRY_SIZE : (index + 1) * ENTRY_SIZE]
            if not is_valid_type_entry(entry):
                raise ValueError(
                    f"runtime type entry {index} fails exact 7.1 structural validation"
                )
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
                    "evidence": "exact 7.1 IL2CPP runtime type array",
                }
            )
            emitted += 1

        boundary_entry = blob[
            EXPECTED_RUNTIME_TYPE_COUNT * ENTRY_SIZE :
            (EXPECTED_RUNTIME_TYPE_COUNT + 1) * ENTRY_SIZE
        ]
        boundary_entry_valid = is_valid_type_entry(boundary_entry)
        if boundary_entry_valid:
            raise ValueError(
                "first entry after verified 7.1 runtime type boundary still looks like Il2CppType"
            )

    if not anchor_found:
        raise ValueError(
            "runtime type index failed mandatory 405772 -> typeDef 84249 DMMJNICDOHM anchor"
        )

    boundary_rva = type_array_rva + EXPECTED_RUNTIME_TYPE_COUNT * ENTRY_SIZE
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
        "runtime_type_count": EXPECTED_RUNTIME_TYPE_COUNT,
        "boundary_rva": f"0x{boundary_rva:X}",
        "boundary_entry_hex": boundary_entry.hex(),
        "boundary_entry_valid_type": boundary_entry_valid,
        "structural_validation_passed": True,
        "include_all_kinds": include_all_kinds,
        "emitted_rows": emitted,
        "class_entries_seen": class_rows,
        "valuetype_entries_seen": value_type_rows,
        "named_definition_entries": valid_named_rows,
        "kind_counts": kind_counts,
        "anchor_405772_class_84249_DMMJNICDOHM": anchor_found,
        "status": "canonical-exact-runtime-type-index",
        "notes": [
            "all 683,574 entries pass the exact-sample Il2CppType structural gate",
            "index 683,574 is the first boundary entry and is required to fail that structural gate",
            "default CSV emits class/valuetype entries that resolve to decoded metadata type names",
            "the preserved 405772 -> typeDef 84249 anchor is mandatory for this exact-sample index",
        ],
    }
    summary_json.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.typearray",
        description="Export the exact-sample 7.1 IL2CPP runtime type-index map.",
    )
    parser.add_argument("exe", type=Path)
    parser.add_argument("types_csv", type=Path)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--all-kinds", action="store_true")
    args = parser.parse_args()

    result = scan_type_array_71(
        args.exe,
        args.types_csv,
        args.output_csv,
        summary_json=args.summary,
        include_all_kinds=args.all_kinds,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
