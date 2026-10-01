from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

HISTORICAL_REGISTRY_SCALE = 4_896

OUTPUT_COLUMNS = (
    "cmd_id",
    "type_name",
    "type_definition_index",
    "get_cmd_id_rva",
    "usage_destination",
    "type_slot_rva",
    "source_encoding",
    "encoded_usage_kind",
    "status",
    "evidence",
)


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def _int(row: dict[str, str], key: str) -> int | None:
    value = str(row.get(key, "")).strip()
    if not value:
        return None
    try:
        return int(value, 0)
    except ValueError:
        return None


def _type_key(row: dict[str, str]) -> tuple[str, object]:
    tdi = _int(row, "type_definition_index")
    if tdi is not None:
        return "tdi", tdi
    return "name", str(row.get("type_name", ""))


def refine_registry_candidates(
    graph_csv: Path,
    output_csv: Path,
    summary_json: Path | None = None,
) -> dict[str, object]:
    rows = _rows(graph_csv)

    by_type: dict[tuple[str, object], list[dict[str, str]]] = defaultdict(list)
    by_cmd: dict[int, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        cmd_id = _int(row, "cmd_id")
        if cmd_id is None:
            continue
        by_type[_type_key(row)].append(row)
        by_cmd[cmd_id].append(row)

    type_cmds = {
        key: {cmd for row in group if (cmd := _int(row, "cmd_id")) is not None}
        for key, group in by_type.items()
    }
    cmd_types = {
        cmd_id: {_type_key(row) for row in group}
        for cmd_id, group in by_cmd.items()
    }

    rejection_counts: Counter[str] = Counter()
    selected: list[dict[str, str]] = []

    for type_key, group in by_type.items():
        cmds = type_cmds[type_key]
        if len(cmds) != 1:
            rejection_counts["type_has_multiple_cmd_ids"] += 1
            continue
        cmd_id = next(iter(cmds))
        if len(cmd_types.get(cmd_id, set())) != 1:
            rejection_counts["cmd_id_maps_multiple_types"] += 1
            continue

        slots = {
            int(slot, 0)
            for row in group
            if (slot := str(row.get("type_slot_rva", "")).strip())
        }
        if len(slots) != 1:
            rejection_counts["type_slot_not_unique"] += 1
            continue
        slot = next(iter(slots))

        # Collapse repeated evidence for the same type/CmdId/slot. A unique native
        # GetCmdId RVA is also required so the row remains auditable.
        getcmd_rvas = {
            int(rva, 0)
            for row in group
            if (rva := str(row.get("get_cmd_id_rva", "")).strip())
        }
        if len(getcmd_rvas) != 1:
            rejection_counts["get_cmd_id_rva_not_unique"] += 1
            continue
        getcmd_rva = next(iter(getcmd_rvas))

        usage_pairs = {
            (
                str(row.get("usage_destination", "")),
                str(row.get("source_encoding", "")),
                str(row.get("encoded_usage_kind", "")),
            )
            for row in group
            if _int(row, "type_slot_rva") == slot
        }
        if len(usage_pairs) != 1:
            rejection_counts["usage_identity_not_unique"] += 1
            continue
        usage_destination, source_encoding, encoded_usage_kind = next(iter(usage_pairs))

        exemplar = group[0]
        selected.append(
            {
                "cmd_id": str(cmd_id),
                "type_name": str(exemplar.get("type_name", "")),
                "type_definition_index": str(exemplar.get("type_definition_index", "")),
                "get_cmd_id_rva": f"0x{getcmd_rva:X}",
                "usage_destination": usage_destination,
                "type_slot_rva": f"0x{slot:X}",
                "source_encoding": source_encoding,
                "encoded_usage_kind": encoded_usage_kind,
                "status": "STATIC_CANDIDATE",
                "evidence": "one-to-one CmdId/type/GetCmdId/type-slot identity in reconstructed 7.1 static graph",
            }
        )

    selected.sort(key=lambda row: int(row["cmd_id"]))
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        writer.writerows(selected)

    selected_ids = {int(row["cmd_id"]) for row in selected}
    summary: dict[str, object] = {
        "input_rows": len(rows),
        "input_unique_types": len(by_type),
        "input_unique_cmd_ids": len(by_cmd),
        "selected_rows": len(selected),
        "selected_unique_cmd_ids": len(selected_ids),
        "rejection_counts": dict(sorted(rejection_counts.items())),
        "historical_registry_scale": HISTORICAL_REGISTRY_SCALE,
        "distance_from_historical_scale": len(selected_ids) - HISTORICAL_REGISTRY_SCALE,
        "status": "strict-static-candidates",
        "notes": [
            "selection is structural evidence only and does not promote rows to canonical registry.csv",
            "no target count is forced; the 4,896 historical scale is reported only as a regression reference",
            "types with multiple constant-return CmdId candidates remain unresolved for later signature/registration analysis",
        ],
    }
    if summary_json is None:
        summary_json = output_csv.with_suffix(".summary.json")
    summary_json.parent.mkdir(parents=True, exist_ok=True)
    summary_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.registryselect",
        description="Conservatively refine a 7.1 registry candidate graph to one-to-one static candidates.",
    )
    parser.add_argument("graph_csv", type=Path)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args()

    result = refine_registry_candidates(args.graph_csv, args.output_csv, args.summary)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
