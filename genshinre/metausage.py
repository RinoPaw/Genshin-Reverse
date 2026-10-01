from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

from .metareg import PAIR_SIZE, QWORD, _find_qword_occurrences, decode_count_pointer_pair
from .mhy71 import EXPECTED_EXE_SHA256, TYPE_ARRAY_POINTER_RVA
from .pe import PEImage

ANCHOR_USAGE_DESTINATION = 37_523
ANCHOR_TYPE_SLOT_RVA = 0x057E6498
MAX_PLAUSIBLE_COUNT = 10_000_000

COLUMNS = (
    "usage_destination",
    "type_slot_va",
    "type_slot_rva",
    "section",
    "status",
    "evidence",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _section_for_rva(image: PEImage, rva: int) -> str | None:
    for section in image.sections:
        if section.virtual_address <= rva < section.virtual_address + max(section.virtual_size, section.raw_size):
            return section.name
    return None


def probe_table_entry(
    image: PEImage,
    count: int,
    pointer_va: int,
    index: int,
    expected_slot_rva: int | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "count": count,
        "table_pointer_va": f"0x{pointer_va:X}",
        "index": index,
        "readable": False,
        "entry_va": None,
        "entry_rva": None,
        "entry_section": None,
        "matches_expected_slot": None if expected_slot_rva is None else False,
    }
    if index < 0 or index >= count or pointer_va < image.image_base:
        return result
    table_rva = pointer_va - image.image_base
    blob = image.read_rva(table_rva + index * QWORD, QWORD)
    if len(blob) != QWORD:
        return result
    entry_va = int.from_bytes(blob, "little", signed=False)
    entry_rva = entry_va - image.image_base if entry_va >= image.image_base else -1
    mapped = entry_rva >= 0 and image.rva_to_offset(entry_rva) is not None
    result.update(
        {
            "readable": True,
            "entry_va": f"0x{entry_va:X}",
            "entry_rva": None if entry_rva < 0 else f"0x{entry_rva:X}",
            "entry_mapped": mapped,
            "entry_section": None if entry_rva < 0 else _section_for_rva(image, entry_rva),
        }
    )
    if expected_slot_rva is not None:
        result["matches_expected_slot"] = entry_rva == expected_slot_rva
    return result


def _registration_pairs_around_type_array(
    image: PEImage,
    pairs_before: int,
    pairs_after: int,
) -> list[dict[str, object]]:
    pointer_blob = image.read_rva(TYPE_ARRAY_POINTER_RVA, QWORD)
    if len(pointer_blob) != QWORD:
        raise ValueError("cannot read runtime type-array pointer source")
    type_array_va = int.from_bytes(pointer_blob, "little", signed=False)
    occurrences = _find_qword_occurrences(image, type_array_va)
    rows: list[dict[str, object]] = []
    seen_sources: set[int] = set()
    for occurrence in occurrences:
        pointer_field_rva = int(occurrence["rva"])
        type_pair_rva = pointer_field_rva - QWORD
        first_pair_rva = type_pair_rva - pairs_before * PAIR_SIZE
        for relative_pair in range(-pairs_before, pairs_after + 1):
            source_rva = type_pair_rva + relative_pair * PAIR_SIZE
            if source_rva in seen_sources:
                continue
            seen_sources.add(source_rva)
            try:
                pair = decode_count_pointer_pair(image, source_rva)
            except ValueError:
                continue
            count = int(pair["count"])
            pointer_va = int(pair["pointer"]["value"], 0)
            if count <= 0 or count >= MAX_PLAUSIBLE_COUNT or not bool(pair["pointer"].get("mapped")):
                continue
            rows.append(
                {
                    "source_rva": source_rva,
                    "source_rva_hex": f"0x{source_rva:X}",
                    "relative_pair": relative_pair,
                    "count": count,
                    "pointer_va": pointer_va,
                    "pointer_va_hex": f"0x{pointer_va:X}",
                    "type_array_occurrence_rva": f"0x{pointer_field_rva:X}",
                }
            )
    return rows


def recover_metadata_usage_table_71(
    exe: Path,
    output_csv: Path,
    summary_json: Path | None = None,
    pairs_before: int = 6,
    pairs_after: int = 10,
    allow_unknown_sample: bool = False,
    require_unique_anchor: bool = True,
) -> dict[str, object]:
    exe_sha = _sha256(exe)
    if not allow_unknown_sample and exe_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"unexpected GenshinImpact.exe SHA-256: {exe_sha}")

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    if summary_json is None:
        summary_json = output_csv.with_suffix(".summary.json")
    summary_json.parent.mkdir(parents=True, exist_ok=True)

    with PEImage(exe) as image:
        candidate_pairs = _registration_pairs_around_type_array(image, pairs_before, pairs_after)
        probes: list[dict[str, object]] = []
        matches: list[dict[str, object]] = []
        for pair in candidate_pairs:
            probe = probe_table_entry(
                image,
                int(pair["count"]),
                int(pair["pointer_va"]),
                ANCHOR_USAGE_DESTINATION,
                ANCHOR_TYPE_SLOT_RVA,
            )
            item = {**pair, "anchor_probe": probe}
            probes.append(item)
            if probe.get("matches_expected_slot") is True:
                matches.append(item)

        if require_unique_anchor and len(matches) != 1:
            summary = {
                "exe": str(exe),
                "exe_sha256": exe_sha,
                "anchor": {
                    "usage_destination": ANCHOR_USAGE_DESTINATION,
                    "type_slot_rva": f"0x{ANCHOR_TYPE_SLOT_RVA:X}",
                },
                "candidate_pair_count": len(candidate_pairs),
                "anchor_match_count": len(matches),
                "anchor_matches": matches,
                "status": "unresolved",
                "notes": [
                    "expected exactly one count/pointer table whose entry 37523 points to the preserved 9369 type slot",
                    "increase the registration pair window or inspect protected-build layout before publishing a usage table",
                ],
            }
            summary_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            raise ValueError(f"metadata usage table anchor matched {len(matches)} candidate pairs; expected exactly 1")

        if not matches:
            selected = None
        else:
            selected = matches[0]

        emitted = 0
        mapped_entries = 0
        duplicate_slots: dict[str, int] = {}
        if selected is not None:
            count = int(selected["count"])
            pointer_va = int(selected["pointer_va"])
            table_rva = pointer_va - image.image_base
            blob = image.read_rva(table_rva, count * QWORD)
            if len(blob) < count * QWORD:
                raise ValueError("selected metadata usage pointer table is truncated")
            slot_counts: dict[int, int] = {}
            with output_csv.open("w", encoding="utf-8", newline="") as out:
                writer = csv.DictWriter(out, fieldnames=COLUMNS)
                writer.writeheader()
                for index in range(count):
                    slot_va = int.from_bytes(blob[index * QWORD : (index + 1) * QWORD], "little", signed=False)
                    slot_rva = slot_va - image.image_base if slot_va >= image.image_base else -1
                    mapped = slot_rva >= 0 and image.rva_to_offset(slot_rva) is not None
                    if mapped:
                        mapped_entries += 1
                        slot_counts[slot_rva] = slot_counts.get(slot_rva, 0) + 1
                    writer.writerow(
                        {
                            "usage_destination": index,
                            "type_slot_va": f"0x{slot_va:X}",
                            "type_slot_rva": "" if slot_rva < 0 else f"0x{slot_rva:X}",
                            "section": "" if slot_rva < 0 else (_section_for_rva(image, slot_rva) or ""),
                            "status": "static-decoded" if mapped else "unmapped",
                            "evidence": "metadata-registration candidate table anchored by usage 37523 -> slot 0x057E6498",
                        }
                    )
                    emitted += 1
            duplicate_slots = {
                f"0x{slot:X}": occurrences
                for slot, occurrences in sorted(slot_counts.items())
                if occurrences > 1
            }
        else:
            output_csv.write_text(",".join(COLUMNS) + "\n", encoding="utf-8")

    summary = {
        "exe": str(exe),
        "exe_sha256": exe_sha,
        "anchor": {
            "usage_destination": ANCHOR_USAGE_DESTINATION,
            "type_slot_rva": f"0x{ANCHOR_TYPE_SLOT_RVA:X}",
        },
        "candidate_pair_count": len(candidate_pairs),
        "anchor_match_count": len(matches),
        "selected_pair": None
        if selected is None
        else {
            "source_rva": selected["source_rva_hex"],
            "relative_pair": selected["relative_pair"],
            "count": selected["count"],
            "pointer_va": selected["pointer_va_hex"],
            "type_array_occurrence_rva": selected["type_array_occurrence_rva"],
        },
        "emitted_rows": emitted,
        "mapped_entries": mapped_entries,
        "duplicate_mapped_slots": duplicate_slots,
        "status": "static-decoded" if selected is not None else "unresolved",
        "notes": [
            "table identity is anchored by the preserved 9369 usage_destination/type-slot pair",
            "the table maps usage destination indices to static slot addresses; message type identity remains a separate join",
        ],
    }
    summary_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.metausage",
        description="Recover the 7.1 metadata usage-destination to static-slot pointer table.",
    )
    parser.add_argument("exe", type=Path)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--pairs-before", type=int, default=6)
    parser.add_argument("--pairs-after", type=int, default=10)
    parser.add_argument("--allow-unknown-sample", action="store_true")
    parser.add_argument("--allow-ambiguous-anchor", action="store_true")
    args = parser.parse_args()

    result = recover_metadata_usage_table_71(
        args.exe,
        args.output_csv,
        summary_json=args.summary,
        pairs_before=args.pairs_before,
        pairs_after=args.pairs_after,
        allow_unknown_sample=args.allow_unknown_sample,
        require_unique_anchor=not args.allow_ambiguous_anchor,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
