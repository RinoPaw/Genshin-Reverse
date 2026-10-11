from __future__ import annotations

import argparse
import csv
import json
import struct
from pathlib import Path

from genshinre.pe import PEImage


def _u64(data: bytes) -> int:
    return struct.unpack_from("<Q", data, 0)[0]


def load_types(path: Path) -> tuple[dict[int, dict[str, str]], int]:
    rows: dict[int, dict[str, str]] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            rows[int(row["type_definition_index"])] = row
    return rows, len(rows)


def load_fields(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def find_registration_field_offset_tables(image: PEImage, type_count: int) -> list[dict[str, int]]:
    """Find the standard IL2CPP metadata-registration field-offset pair.

    On 64-bit IL2CPP, fieldOffsetsCount/fieldOffsets is immediately followed by
    typeDefinitionsSizesCount/typeDefinitionsSizes.  Both counts equal the type
    definition count.  Matching both count/pointer pairs gives a much stronger
    exact-sample signature than scanning for one count alone.
    """

    needle = struct.pack("<Q", type_count)
    out: list[dict[str, int]] = []
    base = image.image_base
    for section in image.sections:
        blob = image.read_rva(section.virtual_address, section.raw_size)
        pos = 0
        while True:
            pos = blob.find(needle, pos)
            if pos < 0:
                break
            if pos + 32 <= len(blob) and blob[pos + 16 : pos + 24] == needle:
                field_offsets_va = _u64(blob[pos + 8 : pos + 16])
                sizes_va = _u64(blob[pos + 24 : pos + 32])
                field_offsets_rva = field_offsets_va - base
                sizes_rva = sizes_va - base
                if (
                    field_offsets_rva > 0
                    and sizes_rva > 0
                    and len(image.read_rva(field_offsets_rva, 8)) == 8
                    and len(image.read_rva(sizes_rva, 8)) == 8
                ):
                    out.append(
                        {
                            "signature_rva": section.virtual_address + pos,
                            "field_offsets_va": field_offsets_va,
                            "field_offsets_rva": field_offsets_rva,
                            "type_definition_sizes_va": sizes_va,
                            "type_definition_sizes_rva": sizes_rva,
                        }
                    )
            pos += 1
    return out


def resolve_field(
    image: PEImage,
    candidate: dict[str, int],
    type_row: dict[str, str],
    field_row: dict[str, str],
) -> dict[str, object]:
    base = image.image_base
    type_index = int(type_row["type_definition_index"])
    field_index = int(field_row["field_index"])
    field_start = int(type_row["field_start"])
    field_count = int(type_row["field_count"])
    ordinal = field_index - field_start
    if not (0 <= ordinal < field_count):
        raise ValueError(
            f"field {field_row['field_name']} index {field_index} is outside "
            f"type {type_row['type_name']} span {field_start}+{field_count}"
        )

    slot_rva = candidate["field_offsets_rva"] + type_index * 8
    slot = image.read_rva(slot_rva, 8)
    if len(slot) != 8:
        raise ValueError(f"field-offset slot for type {type_index} is unreadable")
    per_type_va = _u64(slot)
    per_type_rva = per_type_va - base
    if per_type_rva <= 0:
        raise ValueError(f"invalid field-offset table pointer 0x{per_type_va:X}")

    offset_bytes = image.read_rva(per_type_rva + ordinal * 4, 4)
    if len(offset_bytes) != 4:
        raise ValueError(
            f"field-offset entry for {type_row['type_name']}.{field_row['field_name']} is unreadable"
        )
    runtime_offset = struct.unpack_from("<I", offset_bytes, 0)[0]
    return {
        "type_definition_index": type_index,
        "type_name": type_row["type_name"],
        "field_index": field_index,
        "field_name": field_row["field_name"],
        "field_start": field_start,
        "field_ordinal": ordinal,
        "per_type_offsets_va": f"0x{per_type_va:X}",
        "per_type_offsets_rva": f"0x{per_type_rva:X}",
        "runtime_offset": runtime_offset,
        "runtime_offset_hex": f"0x{runtime_offset:X}",
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Resolve runtime field offsets for the exact 7.1 IL2CPP sample.")
    p.add_argument("exe", type=Path)
    p.add_argument("types_csv", type=Path)
    p.add_argument("fields_csv", type=Path)
    p.add_argument("output_json", type=Path)
    p.add_argument("--field", action="append", default=[], help="TYPE.FIELD, repeatable")
    args = p.parse_args()
    if not args.field:
        raise SystemExit("at least one --field TYPE.FIELD is required")

    types, type_count = load_types(args.types_csv)
    fields = load_fields(args.fields_csv)

    requested: list[tuple[dict[str, str], dict[str, str]]] = []
    for spec in args.field:
        if "." not in spec:
            raise SystemExit(f"bad field spec {spec!r}; expected TYPE.FIELD")
        type_name, field_name = spec.rsplit(".", 1)
        type_matches = [row for row in types.values() if row.get("type_name") == type_name]
        if len(type_matches) != 1:
            raise SystemExit(f"{type_name!r}: expected one type, got {len(type_matches)}")
        type_row = type_matches[0]
        type_index = int(type_row["type_definition_index"])
        field_matches = [
            row
            for row in fields
            if int(row.get("type_definition_index") or -1) == type_index
            and row.get("field_name") == field_name
        ]
        if len(field_matches) != 1:
            raise SystemExit(
                f"{type_name}.{field_name}: expected one field, got {len(field_matches)}"
            )
        requested.append((type_row, field_matches[0]))

    with PEImage(args.exe) as image:
        candidates = find_registration_field_offset_tables(image, type_count)
        resolved_candidates: list[dict[str, object]] = []
        for candidate in candidates:
            item: dict[str, object] = {
                "signature_rva": f"0x{candidate['signature_rva']:X}",
                "field_offsets_va": f"0x{candidate['field_offsets_va']:X}",
                "field_offsets_rva": f"0x{candidate['field_offsets_rva']:X}",
                "type_definition_sizes_va": f"0x{candidate['type_definition_sizes_va']:X}",
                "type_definition_sizes_rva": f"0x{candidate['type_definition_sizes_rva']:X}",
                "fields": [],
            }
            failures: list[str] = []
            for type_row, field_row in requested:
                try:
                    item["fields"].append(resolve_field(image, candidate, type_row, field_row))
                except ValueError as exc:
                    failures.append(str(exc))
            item["failures"] = failures
            resolved_candidates.append(item)

    valid = [item for item in resolved_candidates if not item["failures"]]
    payload = {
        "type_definition_count": type_count,
        "registration_candidate_count": len(resolved_candidates),
        "valid_candidate_count": len(valid),
        "candidates": resolved_candidates,
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(
        f"type_definitions={type_count} registration_candidates={len(resolved_candidates)} "
        f"valid_candidates={len(valid)}"
    )
    for candidate in valid:
        print("REGISTRATION", candidate["signature_rva"], "fieldOffsets", candidate["field_offsets_rva"])
        for field in candidate["fields"]:
            print(
                "FIELD",
                f"{field['type_name']}.{field['field_name']}",
                "ordinal=", field["field_ordinal"],
                "offset=", field["runtime_offset_hex"],
            )
    if len(valid) != 1:
        raise SystemExit(f"expected exactly one valid metadata-registration candidate, got {len(valid)}")


if __name__ == "__main__":
    main()
