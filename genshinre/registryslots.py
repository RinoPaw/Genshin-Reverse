from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

from .nativeprofile import PROFILE_71
from .pe import PEImage

EXPECTED_REGISTRY_ROWS = 4896
DEST_BASE = 0x20
ENTRY_SIZE = 8

# Exact 7.1 global client protocol-registry construction corridor. The first
# observed indexed stores begin immediately above 0x7F7D800 and the final row
# (4895) stores at 0x7F8E44D. Restricting candidate loads to this constructor
# removes unrelated [rbx+offset] stores elsewhere in il2cpp code.
REGISTRY_CODE_MIN_RVA = 0x07F7D800
REGISTRY_CODE_MAX_RVA = 0x07F8E500

ANCHORS = {
    2232: {"type_slot_rva": 0x057E6498, "store_rva": 0x07F852AB, "name": "UnlockTransPointReq"},
    3118: {"type_slot_rva": 0x057F6F60, "store_rva": None, "name": "DoSetPlayerBornDataNotify"},
}

COLUMNS = (
    "index",
    "type_slot_rva",
    "load_rva",
    "store_rva",
    "destination_offset",
    "section",
    "status",
    "evidence",
)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def recover_registry_type_slots_71(
    exe: Path,
    output_csv: Path,
    summary_json: Path | None = None,
) -> dict[str, object]:
    exe_sha = _sha256(exe)
    if exe_sha != PROFILE_71.exe_sha256:
        raise ValueError(f"unexpected GenshinImpact.exe SHA-256: {exe_sha}")

    # Observed 7.1 bulk registry construction forms:
    #   48 8B 05 disp32        mov rax, qword ptr [rip + type_slot]
    #   48 89 43 disp8         mov qword ptr [rbx + offset], rax   (indices 0..11)
    #   48 89 83 disp32        mov qword ptr [rbx + offset], rax   (indices 12..4895)
    # The preserved row 2232 is exactly load@0x7F852A4/store@0x7F852AB.
    matches: dict[int, list[dict[str, object]]] = {}
    pattern_prefix = b"\x48\x8B\x05"
    pattern_store8 = b"\x48\x89\x43"
    pattern_store32 = b"\x48\x89\x83"

    with PEImage(exe) as image:
        virtual_ranges = [
            (
                section.virtual_address,
                section.virtual_address + max(section.virtual_size, section.raw_size),
            )
            for section in image.sections
        ]

        for section in image.sections:
            if not (section.characteristics & 0x20000000):
                continue
            blob = image.read_rva(section.virtual_address, section.raw_size)
            if not blob:
                raise ValueError(f"failed to read executable section {section.name!r}")

            cursor = 0
            limit = len(blob) - 11
            while cursor <= limit:
                off = blob.find(pattern_prefix, cursor)
                if off < 0 or off > limit:
                    break
                cursor = off + 1

                load_rva = section.virtual_address + off
                if not REGISTRY_CODE_MIN_RVA <= load_rva < REGISTRY_CODE_MAX_RVA:
                    continue

                store_prefix = blob[off + 7 : off + 10]
                if store_prefix == pattern_store8:
                    dest = blob[off + 10]
                elif store_prefix == pattern_store32:
                    if off + 14 > len(blob):
                        raise ValueError(f"truncated registry store at RVA 0x{load_rva:X}")
                    dest = int.from_bytes(blob[off + 10 : off + 14], "little", signed=False)
                else:
                    continue

                if dest < DEST_BASE or (dest - DEST_BASE) % ENTRY_SIZE:
                    continue
                index = (dest - DEST_BASE) // ENTRY_SIZE
                if not 0 <= index < EXPECTED_REGISTRY_ROWS:
                    continue

                disp = int.from_bytes(blob[off + 3 : off + 7], "little", signed=True)
                type_slot_rva = load_rva + 7 + disp
                if not any(start <= type_slot_rva < end for start, end in virtual_ranges):
                    continue
                row = {
                    "index": index,
                    "type_slot_rva": type_slot_rva,
                    "load_rva": load_rva,
                    "store_rva": load_rva + 7,
                    "destination_offset": dest,
                    "section": section.name,
                }
                matches.setdefault(index, []).append(row)

    unique_rows: list[dict[str, object]] = []
    ambiguous: list[dict[str, object]] = []
    for index in range(EXPECTED_REGISTRY_ROWS):
        rows = matches.get(index, [])
        identities = {
            (int(row["type_slot_rva"]), int(row["load_rva"]), int(row["store_rva"]))
            for row in rows
        }
        if len(identities) == 1:
            unique_rows.append(rows[0])
        elif rows:
            ambiguous.append(
                {
                    "index": index,
                    "candidates": [
                        {
                            "type_slot_rva": f"0x{int(row['type_slot_rva']):X}",
                            "load_rva": f"0x{int(row['load_rva']):X}",
                            "store_rva": f"0x{int(row['store_rva']):X}",
                        }
                        for row in rows[:20]
                    ],
                }
            )

    by_index = {int(row["index"]): row for row in unique_rows}
    anchor_results: dict[str, object] = {}
    all_anchors = True
    for index, anchor in ANCHORS.items():
        row = by_index.get(index)
        slot_ok = row is not None and int(row["type_slot_rva"]) == int(anchor["type_slot_rva"])
        expected_store = anchor["store_rva"]
        store_ok = expected_store is None or (
            row is not None and int(row["store_rva"]) == int(expected_store)
        )
        ok = bool(slot_ok and store_ok)
        all_anchors &= ok
        anchor_results[str(index)] = {
            "name": anchor["name"],
            "expected_type_slot_rva": f"0x{int(anchor['type_slot_rva']):X}",
            "expected_store_rva": None
            if expected_store is None
            else f"0x{int(expected_store):X}",
            "matched": ok,
            "observed": None
            if row is None
            else {
                "type_slot_rva": f"0x{int(row['type_slot_rva']):X}",
                "load_rva": f"0x{int(row['load_rva']):X}",
                "store_rva": f"0x{int(row['store_rva']):X}",
            },
        }

    missing_indices = [
        index for index in range(EXPECTED_REGISTRY_ROWS) if index not in by_index
    ]
    complete = len(unique_rows) == EXPECTED_REGISTRY_ROWS and not ambiguous and all_anchors
    if not complete:
        raise ValueError(
            "registry type-slot recovery did not close exact 7.1 contract: "
            f"unique={len(unique_rows)} missing={missing_indices[:20]} "
            f"ambiguous={len(ambiguous)} anchors={all_anchors}"
        )

    summary: dict[str, object] = {
        "exe_sha256": exe_sha,
        "expected_row_count": EXPECTED_REGISTRY_ROWS,
        "matched_unique_indices": len(unique_rows),
        "missing_indices": [],
        "ambiguous_indices": [],
        "anchors": anchor_results,
        "all_anchors_pass": True,
        "complete_4896_indexed_type_slots": True,
        "status": "static-verified",
        "layout": {
            "destination_base": f"0x{DEST_BASE:X}",
            "entry_size": ENTRY_SIZE,
            "load_pattern": "48 8B 05 disp32",
            "store_patterns": ["48 89 43 disp8", "48 89 83 disp32"],
            "type_slot_validation": "PE virtual section span; raw backing not required",
            "registry_code_rva_range": [
                f"0x{REGISTRY_CODE_MIN_RVA:X}",
                f"0x{REGISTRY_CODE_MAX_RVA:X}",
            ],
        },
    }

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        for row in sorted(unique_rows, key=lambda item: int(item["index"])):
            writer.writerow(
                {
                    "index": row["index"],
                    "type_slot_rva": f"0x{int(row['type_slot_rva']):X}",
                    "load_rva": f"0x{int(row['load_rva']):X}",
                    "store_rva": f"0x{int(row['store_rva']):X}",
                    "destination_offset": f"0x{int(row['destination_offset']):X}",
                    "section": row["section"],
                    "status": "static-verified",
                    "evidence": "7.1 protocol registry constructor type-slot sequence",
                }
            )

    if summary_json is None:
        summary_json = output_csv.with_suffix(".summary.json")
    summary_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.registryslots",
        description="Recover the exact pinned-7.1 protocol-registry type-slot construction table.",
    )
    parser.add_argument("exe", type=Path)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args()

    result = recover_registry_type_slots_71(
        args.exe,
        args.output_csv,
        summary_json=args.summary,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
