from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

ANCHOR_USAGE_DESTINATION = 37_523
ANCHOR_TYPE_SLOT_RVA = 0x057E6498

COLUMNS = (
    "usage_destination",
    "type_slot_va",
    "type_slot_rva",
    "section",
    "status",
    "evidence",
)


def _parse_int(value: object) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def recover_slots_from_usage_sites(
    usage_sites_csv: Path,
    output_csv: Path,
    summary_json: Path | None = None,
    image_base: int = 0x140000000,
    require_anchor: bool = False,
) -> dict[str, object]:
    """Collapse initializer call-site evidence into stable usage->slot mappings.

    `usage.py` observes the client-side initialization sequence directly. The same
    usage destination can occur at many call sites; a mapping is emitted only when
    every usable observation for that destination resolves to one static slot RVA.
    Ambiguous destinations are deliberately omitted and reported in the summary.

    The preserved 37523 -> 0x57E6498 identity is retained as a regression diagnostic.
    Current 7.1 generation does not require that historical usage index to remain
    stable; downstream joining can select its source table from global type evidence.
    """

    groups: dict[int, dict[int, list[dict[str, str]]]] = defaultdict(lambda: defaultdict(list))
    input_rows = 0
    usable_rows = 0

    with usage_sites_csv.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            input_rows += 1
            usage = _parse_int(row.get("usage_destination"))
            slot = _parse_int(row.get("type_slot_rva"))
            if usage is None or slot is None:
                continue
            usable_rows += 1
            groups[usage][slot].append(row)

    stable: list[tuple[int, int, list[dict[str, str]]]] = []
    ambiguous: list[dict[str, object]] = []
    for usage, slots in sorted(groups.items()):
        if len(slots) == 1:
            slot, rows = next(iter(slots.items()))
            stable.append((usage, slot, rows))
        else:
            ambiguous.append(
                {
                    "usage_destination": usage,
                    "slots": [f"0x{slot:X}" for slot in sorted(slots)],
                    "observations": sum(len(rows) for rows in slots.values()),
                }
            )

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=COLUMNS)
        writer.writeheader()
        for usage, slot, rows in stable:
            sections = sorted({str(row.get("section", "")).strip() for row in rows if str(row.get("section", "")).strip()})
            writer.writerow(
                {
                    "usage_destination": usage,
                    "type_slot_va": f"0x{image_base + slot:X}",
                    "type_slot_rva": f"0x{slot:X}",
                    "section": "|".join(sections),
                    "status": "static-observed",
                    "evidence": f"{len(rows)} initializer call-site observation(s); unanimous slot",
                }
            )

    anchor_rows = [
        (usage, slot)
        for usage, slot, _ in stable
        if usage == ANCHOR_USAGE_DESTINATION and slot == ANCHOR_TYPE_SLOT_RVA
    ]
    anchor_ok = len(anchor_rows) == 1

    summary: dict[str, object] = {
        "source": str(usage_sites_csv),
        "input_rows": input_rows,
        "usable_rows": usable_rows,
        "unique_usage_destinations_with_slots": len(groups),
        "stable_mappings": len(stable),
        "ambiguous_usage_destinations": len(ambiguous),
        "ambiguous_examples": ambiguous[:50],
        "legacy_anchor_37523_to_0x57E6498": anchor_ok,
        "status": "static-callsite-map",
        "notes": [
            "mappings come from direct initializer call/store evidence",
            "a usage destination is emitted only when all usable call-site observations agree on one slot",
            "ambiguous destinations remain excluded rather than guessed",
            "the historical 37523 anchor is diagnostic and is not required for current 7.1 output",
        ],
    }
    if summary_json is None:
        summary_json = output_csv.with_suffix(".summary.json")
    summary_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    if require_anchor and not anchor_ok:
        raise ValueError("call-site usage map failed preserved 37523 -> 0x57E6498 anchor")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.usageslots",
        description="Recover stable 7.1 usage-destination -> type-slot mappings from initializer call sites.",
    )
    parser.add_argument("usage_sites_csv", type=Path)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--image-base", type=lambda value: int(value, 0), default=0x140000000)
    parser.add_argument("--require-anchor", action="store_true")
    args = parser.parse_args()

    result = recover_slots_from_usage_sites(
        args.usage_sites_csv,
        args.output_csv,
        summary_json=args.summary,
        image_base=args.image_base,
        require_anchor=args.require_anchor,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
