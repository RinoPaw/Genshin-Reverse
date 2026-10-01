from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

COLUMNS = (
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

ANCHORS = (
    {
        "cmd_id": 9369,
        "type_name": "DMMJNICDOHM",
        "type_definition_index": 84249,
        "get_cmd_id_rva": 0x0C87EA60,
        "usage_destination": 37523,
        "type_slot_rva": 0x057E6498,
    },
    {
        "cmd_id": 26105,
        "type_name": "HJDNCHODGOL",
        "get_cmd_id_rva": 0x10587260,
    },
    {
        "cmd_id": 22899,
        "type_name": "ONKOPMILDMF",
        "type_definition_index": 87483,
        "type_slot_rva": 0x057F6F60,
    },
)


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _int(row: dict[str, str], key: str) -> int | None:
    text = str(row.get(key, "")).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _type_key(row: dict[str, str]) -> tuple[str, object]:
    tdi = _int(row, "type_definition_index")
    if tdi is not None:
        return "tdi", tdi
    return "name", str(row.get("type_name", ""))


def _anchor_result(rows: list[dict[str, str]], anchor: dict[str, object]) -> dict[str, object]:
    matches = [row for row in rows if _int(row, "cmd_id") == int(anchor["cmd_id"])]
    checks: dict[str, bool] = {}
    for field, expected in anchor.items():
        if field == "cmd_id":
            continue
        if field in {"type_definition_index", "get_cmd_id_rva", "usage_destination", "type_slot_rva"}:
            checks[field] = any(_int(row, field) == int(expected) for row in matches)
        else:
            checks[field] = any(str(row.get(field, "")) == str(expected) for row in matches)
    return {
        "cmd_id": anchor["cmd_id"],
        "match_rows": len(matches),
        "checks": checks,
        "passed": bool(matches) and all(checks.values()),
    }


def build_registry_candidate_graph(
    usage_types_csv: Path,
    getcmdid_candidates_csv: Path,
    output_csv: Path,
    summary_json: Path | None = None,
) -> dict[str, object]:
    usage_rows = _rows(usage_types_csv)
    cmd_rows = _rows(getcmdid_candidates_csv)

    by_key: dict[tuple[str, object], list[dict[str, str]]] = defaultdict(list)
    by_name: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in usage_rows:
        by_key[_type_key(row)].append(row)
        name = str(row.get("type_name", ""))
        if name:
            by_name[name].append(row)

    emitted: list[dict[str, str]] = []
    unmatched_getcmdid = 0
    ambiguous_getcmdid = 0

    for cmd in cmd_rows:
        key = _type_key(cmd)
        matches = by_key.get(key, [])
        if not matches:
            name = str(cmd.get("type_name", ""))
            matches = by_name.get(name, []) if name else []
        if not matches:
            unmatched_getcmdid += 1
            continue
        if len(matches) > 1:
            ambiguous_getcmdid += 1
        for usage in matches:
            status = "JOINED_UNIQUE" if len(matches) == 1 else "JOINED_AMBIGUOUS_USAGE"
            emitted.append(
                {
                    "cmd_id": str(cmd.get("cmd_id", "")),
                    "type_name": str(cmd.get("type_name", "")),
                    "type_definition_index": str(cmd.get("type_definition_index", "")),
                    "get_cmd_id_rva": str(cmd.get("get_cmd_id_rva", "")),
                    "usage_destination": str(usage.get("usage_destination", "")),
                    "type_slot_rva": str(usage.get("type_slot_rva", "")),
                    "source_encoding": str(usage.get("source_encoding", "")),
                    "encoded_usage_kind": str(usage.get("encoded_usage_kind", "")),
                    "status": status,
                    "evidence": "GetCmdId constant-return candidate joined to anchored metadata usage/runtime type identity",
                }
            )

    # A protocol type can appear more than once in raw discovery. Keep exact duplicate
    # evidence out of the graph while retaining genuine usage ambiguity as separate rows.
    unique_rows: dict[tuple[str, ...], dict[str, str]] = {}
    key_fields = tuple(column for column in COLUMNS if column not in {"status", "evidence"})
    for row in emitted:
        unique_rows[tuple(row[field] for field in key_fields)] = row
    emitted = sorted(
        unique_rows.values(),
        key=lambda row: (
            int(row["cmd_id"]) if row["cmd_id"].isdigit() else 1 << 30,
            row["type_name"],
            row["type_slot_rva"],
        ),
    )

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(emitted)

    cmd_counts = Counter(_int(row, "cmd_id") for row in emitted)
    cmd_counts.pop(None, None)
    unique_cmd_ids = len(cmd_counts)
    duplicate_cmd_ids = {str(cmd): count for cmd, count in sorted(cmd_counts.items()) if count > 1}
    anchor_results = [_anchor_result(emitted, anchor) for anchor in ANCHORS]

    summary: dict[str, object] = {
        "usage_type_rows": len(usage_rows),
        "getcmdid_candidate_rows": len(cmd_rows),
        "joined_rows": len(emitted),
        "unique_cmd_ids": unique_cmd_ids,
        "duplicate_cmd_ids": duplicate_cmd_ids,
        "unmatched_getcmdid_candidates": unmatched_getcmdid,
        "ambiguous_getcmdid_candidates": ambiguous_getcmdid,
        "historical_registry_scale": 4896,
        "distance_from_historical_scale": unique_cmd_ids - 4896,
        "anchors": anchor_results,
        "all_preserved_anchors_pass": all(item["passed"] for item in anchor_results),
        "status": "candidate-graph",
        "notes": [
            "this graph is discovery evidence; it is not canonical registry.csv until registration-table identity is independently closed",
            "a natural convergence near 4,896 unique CmdIds is a regression signal, never a target to force",
            "non-protocol constant-return methods may remain and must be filtered by registration evidence",
        ],
    }
    if summary_json is None:
        summary_json = output_csv.with_suffix(".summary.json")
    summary_json.parent.mkdir(parents=True, exist_ok=True)
    summary_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.registrygraph",
        description="Join 7.1 metadata usage/runtime type identities with GetCmdId candidates.",
    )
    parser.add_argument("usage_types_csv", type=Path)
    parser.add_argument("getcmdid_candidates_csv", type=Path)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--require-anchors", action="store_true")
    args = parser.parse_args()

    result = build_registry_candidate_graph(
        args.usage_types_csv,
        args.getcmdid_candidates_csv,
        args.output_csv,
        summary_json=args.summary,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if args.require_anchors and not result["all_preserved_anchors_pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
