from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

EXPECTED_ROWS = 4896
PRIMARY_STATUSES = {"UNIQUE_SLOT_XREF", "DOMINANT_SLOT_XREF"}
ANCHORS = {
    9369: {"index": 2232, "slot": 0x057E6498, "type_name": "DMMJNICDOHM", "tdi": 84249},
    22899: {"index": 3118, "slot": 0x057F6F60, "type_name": "ONKOPMILDMF", "tdi": 87483},
}

COLUMNS = (
    "index",
    "cmd_id",
    "type_name",
    "type_definition_index",
    "direction",
    "direction_status",
    "semantic_name",
    "type_slot_rva",
    "get_cmd_id_rva",
    "get_cmd_id_method",
    "load_rva",
    "store_rva",
    "xref_count",
    "xref_method_count",
    "status",
    "evidence",
)


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def _int(value: object) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def publish_registry_from_xrefs_71(
    xrefs_csv: Path,
    slots_csv: Path,
    known_opcodes_csv: Path,
    output_csv: Path,
    summary_json: Path | None = None,
) -> dict[str, object]:
    xref_rows = _rows(xrefs_csv)
    slot_rows = _rows(slots_csv)
    known_rows = _rows(known_opcodes_csv)

    slots_by_rva: dict[int, dict[str, str]] = {}
    slots_by_index: dict[int, dict[str, str]] = {}
    for row in slot_rows:
        slot = _int(row.get("type_slot_rva"))
        index = _int(row.get("index"))
        if slot is None or index is None:
            raise ValueError("registry type-slot row lacks slot/index")
        if slot in slots_by_rva:
            raise ValueError(f"duplicate verified registry slot 0x{slot:X}")
        if index in slots_by_index:
            raise ValueError(f"duplicate verified registry index {index}")
        slots_by_rva[slot] = row
        slots_by_index[index] = row
    if len(slot_rows) != EXPECTED_ROWS or len(slots_by_rva) != EXPECTED_ROWS:
        raise ValueError(f"verified constructor slot population is not exactly {EXPECTED_ROWS}")
    if set(slots_by_index) != set(range(EXPECTED_ROWS)):
        raise ValueError("verified constructor indices do not cover 0..4895 exactly")

    primary_by_type: dict[int, list[dict[str, str]]] = defaultdict(list)
    for row in xref_rows:
        if str(row.get("status", "")) not in PRIMARY_STATUSES:
            continue
        tdi = _int(row.get("type_definition_index"))
        if tdi is None:
            raise ValueError("primary xref row lacks type_definition_index")
        primary_by_type[tdi].append(row)

    duplicate_primary_types = {
        str(tdi): len(rows) for tdi, rows in primary_by_type.items() if len(rows) != 1
    }
    if duplicate_primary_types:
        raise ValueError(f"types have non-unique primary slot rows: {dict(list(duplicate_primary_types.items())[:20])}")

    primary_rows = [rows[0] for rows in primary_by_type.values()]
    if len(primary_rows) != EXPECTED_ROWS:
        raise ValueError(f"primary xref identity count {len(primary_rows)} != {EXPECTED_ROWS}")

    selected_slots: Counter[int] = Counter()
    selected_cmds: Counter[int] = Counter()
    selected_types: Counter[int] = Counter()
    for row in primary_rows:
        slot = _int(row.get("registry_slot_rva"))
        cmd_id = _int(row.get("cmd_id"))
        tdi = _int(row.get("type_definition_index"))
        if slot is None or cmd_id is None or tdi is None:
            raise ValueError("primary xref row lacks slot/CmdId/type identity")
        if slot not in slots_by_rva:
            raise ValueError(f"primary xref references unverified slot 0x{slot:X}")
        selected_slots[slot] += 1
        selected_cmds[cmd_id] += 1
        selected_types[tdi] += 1

    duplicate_top_slots = {f"0x{k:X}": v for k, v in selected_slots.items() if v != 1}
    duplicate_cmd_ids = {str(k): v for k, v in selected_cmds.items() if v != 1}
    duplicate_types = {str(k): v for k, v in selected_types.items() if v != 1}
    missing_slots = sorted(set(slots_by_rva) - set(selected_slots))
    if duplicate_top_slots or duplicate_cmd_ids or duplicate_types or missing_slots:
        raise ValueError(
            "dominant xref mapping is not a strict slot/type/CmdId bijection: "
            f"duplicate_slots={dict(list(duplicate_top_slots.items())[:10])}, "
            f"duplicate_cmd_ids={dict(list(duplicate_cmd_ids.items())[:10])}, "
            f"duplicate_types={dict(list(duplicate_types.items())[:10])}, "
            f"missing_slots={[f'0x{x:X}' for x in missing_slots[:10]]}"
        )

    known_by_cmd: dict[int, dict[str, str]] = {}
    for row in known_rows:
        cmd_id = _int(row.get("cmd_id"))
        if cmd_id is None:
            continue
        if cmd_id in known_by_cmd and known_by_cmd[cmd_id].get("semantic_name") != row.get("semantic_name"):
            raise ValueError(f"known opcode controls contain conflicting CmdId {cmd_id}")
        known_by_cmd[cmd_id] = row

    selected_by_slot = {_int(row["registry_slot_rva"]): row for row in primary_rows}
    output: list[dict[str, str]] = []
    anchor_results: dict[str, object] = {}
    for index in range(EXPECTED_ROWS):
        slot_row = slots_by_index[index]
        slot = _int(slot_row["type_slot_rva"])
        assert slot is not None
        identity = selected_by_slot[slot]
        cmd_id = _int(identity["cmd_id"])
        tdi = _int(identity["type_definition_index"])
        assert cmd_id is not None and tdi is not None
        known = known_by_cmd.get(cmd_id, {})
        direction = str(known.get("direction", "")).strip()
        semantic_name = str(known.get("semantic_name", "")).strip()
        output.append(
            {
                "index": str(index),
                "cmd_id": str(cmd_id),
                "type_name": str(identity.get("type_name", "")),
                "type_definition_index": str(tdi),
                "direction": direction,
                "direction_status": "control-confirmed" if direction else "unresolved",
                "semantic_name": semantic_name,
                "type_slot_rva": f"0x{slot:X}",
                "get_cmd_id_rva": str(identity.get("get_cmd_id_rva", "")),
                "get_cmd_id_method": "AEGNNPENLNM",
                "load_rva": str(slot_row.get("load_rva", "")),
                "store_rva": str(slot_row.get("store_rva", "")),
                "xref_count": str(identity.get("xref_count", "")),
                "xref_method_count": str(identity.get("xref_method_count", "")),
                "status": "static-verified-identity",
                "evidence": "verified 7.1 registry constructor slot + dominant declaring-type RIP-relative slot xref + AEGNNPENLNM GetCmdId constant-return identity",
            }
        )

    for cmd_id, expected in ANCHORS.items():
        hits = [row for row in output if int(row["cmd_id"]) == cmd_id]
        ok = (
            len(hits) == 1
            and int(hits[0]["index"]) == int(expected["index"])
            and int(hits[0]["type_slot_rva"], 0) == int(expected["slot"])
            and hits[0]["type_name"] == expected["type_name"]
            and int(hits[0]["type_definition_index"]) == int(expected["tdi"])
        )
        anchor_results[str(cmd_id)] = {"passed": ok, "observed": hits[0] if len(hits) == 1 else hits}
    if not all(item["passed"] for item in anchor_results.values()):
        raise ValueError(f"preserved registry anchors failed: {anchor_results}")

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(output)

    direction_counts = Counter(row["direction"] or "unresolved" for row in output)
    summary: dict[str, object] = {
        "row_count": len(output),
        "unique_cmd_ids": len(selected_cmds),
        "unique_type_definition_indices": len(selected_types),
        "unique_registry_slots": len(selected_slots),
        "index_range": [0, EXPECTED_ROWS - 1],
        "direction_counts": dict(direction_counts),
        "semantic_name_count": sum(bool(row["semantic_name"]) for row in output),
        "anchors": anchor_results,
        "strict_slot_type_cmd_bijection": True,
        "status": "canonical-static-identity-registry",
        "notes": [
            "all 4,896 identities are closed by a verified constructor slot and a unique dominant code-xref owner",
            "the 27 AEGNNPENLNM constant-return candidate types with no verified registry-slot xref are excluded structurally",
            "direction and semantic labels are supplemental control-set evidence and remain blank when unresolved",
        ],
    }
    if summary_json is None:
        summary_json = output_csv.with_suffix(".summary.json")
    summary_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m genshinre.registryxrefpublish")
    parser.add_argument("xrefs_csv", type=Path)
    parser.add_argument("slots_csv", type=Path)
    parser.add_argument("known_opcodes_csv", type=Path)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args()
    result = publish_registry_from_xrefs_71(
        args.xrefs_csv,
        args.slots_csv,
        args.known_opcodes_csv,
        args.output_csv,
        summary_json=args.summary,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
