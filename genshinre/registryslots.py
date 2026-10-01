from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

from .mhy71 import EXPECTED_EXE_SHA256
from .pe import PEImage

HISTORICAL_ROW_COUNT = 4896
DEST_BASE = 0x20
ENTRY_SIZE = 8

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
    allow_unknown_sample: bool = False,
) -> dict[str, object]:
    exe_sha = _sha256(exe)
    if not allow_unknown_sample and exe_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"unexpected GenshinImpact.exe SHA-256: {exe_sha}")

    # Observed 7.1 bulk registry construction form:
    #   48 8B 05 disp32        mov rax, qword ptr [rip + type_slot]
    #   48 89 83 disp32        mov qword ptr [rbx + 0x20 + index*8], rax
    # The historical row 2232 is exactly load@0x7F852A4/store@0x7F852AB.
    matches: dict[int, list[dict[str, object]]] = {}
    pattern_prefix = b"\x48\x8B\x05"
    pattern_store = b"\x48\x89\x83"

    with PEImage(exe) as image:
        # IL2CPP type pointer slots frequently live in virtual-only tails of PE
        # sections (zero-filled at load time). rva_to_offset() intentionally
        # rejects those RVAs, so registry recovery must validate against the
        # section's virtual span instead of requiring raw-file backing.
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
                continue

            # Jump directly between candidate MOV-load prefixes instead of walking
            # every byte in the executable. This keeps the evidence rule identical
            # while making the 400+ MB 7.1 client scan practical in CI.
            cursor = 0
            limit = len(blob) - 14
            while cursor <= limit:
                off = blob.find(pattern_prefix, cursor)
                if off < 0 or off > limit:
                    break
                cursor = off + 1
                if blob[off + 7 : off + 10] != pattern_store:
                    continue
                dest = int.from_bytes(blob[off + 10 : off + 14], "little", signed=False)
                if dest < DEST_BASE or (dest - DEST_BASE) % ENTRY_SIZE:
                    continue
                index = (dest - DEST_BASE) // ENTRY_SIZE
                if not 0 <= index < HISTORICAL_ROW_COUNT:
                    continue

                load_rva = section.virtual_address + off
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
    for index in range(HISTORICAL_ROW_COUNT):
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
        store_ok = expected_store is None or (row is not None and int(row["store_rva"]) == int(expected_store))
        ok = bool(slot_ok and store_ok)
        all_anchors &= ok
        anchor_results[str(index)] = {
            "name": anchor["name"],
            "expected_type_slot_rva": f"0x{int(anchor['type_slot_rva']):X}",
            "expected_store_rva": None if expected_store is None else f"0x{int(expected_store):X}",
            "matched": ok,
            "observed": None
            if row is None
            else {
                "type_slot_rva": f"0x{int(row['type_slot_rva']):X}",
                "load_rva": f"0x{int(row['load_rva']):X}",
                "store_rva": f"0x{int(row['store_rva']):X}",
            },
        }

    complete = len(unique_rows) == HISTORICAL_ROW_COUNT and not ambiguous and all_anchors
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
                    "status": "static-verified" if complete else "static-observed",
                    "evidence": "7.1 bulk registry type-slot construction sequence",
                }
            )

    summary: dict[str, object] = {
        "exe_sha256": exe_sha,
        "historical_row_count": HISTORICAL_ROW_COUNT,
        "matched_unique_indices": len(unique_rows),
        "missing_indices": [index for index in range(HISTORICAL_ROW_COUNT) if index not in by_index],
        "ambiguous_indices": ambiguous,
        "anchors": anchor_results,
        "all_anchors_pass": all_anchors,
        "complete_4896_indexed_type_slots": complete,
        "status": "static-verified" if complete else "partial-static-evidence",
        "layout": {
            "destination_base": f"0x{DEST_BASE:X}",
            "entry_size": ENTRY_SIZE,
            "load_pattern": "48 8B 05 disp32",
            "store_pattern": "48 89 83 disp32",
            "type_slot_validation": "PE virtual section span; raw backing not required",
        },
    }
    if summary_json is None:
        summary_json = output_csv.with_suffix(".summary.json")
    summary_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.registryslots",
        description="Recover the indexed 7.1 protocol-registry type-slot construction table.",
    )
    parser.add_argument("exe", type=Path)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--allow-unknown-sample", action="store_true")
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()

    result = recover_registry_type_slots_71(
        args.exe,
        args.output_csv,
        summary_json=args.summary,
        allow_unknown_sample=args.allow_unknown_sample,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if args.require_complete and not result["complete_4896_indexed_type_slots"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
