from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path


OUTPUT_COLUMNS = (
    "cmd_id",
    "type_name",
    "type_definition_index",
    "get_cmd_id_rva",
    "method_name",
    "pattern",
    "status",
    "evidence",
)


def build_getcmdid_candidate_graph(
    input_csv: Path,
    output_csv: Path,
    summary_json: Path,
    *,
    anchor_cmd_id: int,
    anchor_type_name: str,
    anchor_rva: int,
    pattern: str = "mov-ax-imm16-ret",
    focus_cmd_ids: tuple[int, ...] = (),
) -> dict[str, object]:
    with input_csv.open("r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))

    anchors = [
        row
        for row in rows
        if int(row.get("cmd_id", -1)) == anchor_cmd_id
        and row.get("type_name") == anchor_type_name
        and int(row.get("get_cmd_id_rva", "0"), 0) == anchor_rva
    ]
    if len(anchors) != 1:
        raise ValueError(
            "expected exactly one GetCmdId anchor "
            f"{anchor_cmd_id}/{anchor_type_name}/0x{anchor_rva:X}, got {len(anchors)}"
        )
    anchor_method_name = str(anchors[0].get("method_name", ""))
    if not anchor_method_name:
        raise ValueError("GetCmdId anchor has no method_name")

    selected: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for row in rows:
        if row.get("method_name") != anchor_method_name:
            continue
        if row.get("pattern") != pattern:
            continue
        key = (
            str(row.get("cmd_id", "")),
            str(row.get("type_name", "")),
            str(row.get("type_definition_index", "")),
            str(row.get("get_cmd_id_rva", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        selected.append(
            {
                "cmd_id": key[0],
                "type_name": key[1],
                "type_definition_index": key[2],
                "get_cmd_id_rva": key[3],
                "method_name": anchor_method_name,
                "pattern": pattern,
                "status": "static-candidate",
                "evidence": (
                    "same GetCmdId method identity as the verified anchor + "
                    f"{pattern}"
                ),
            }
        )

    selected.sort(key=lambda row: (int(row["cmd_id"]), row["type_name"]))
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        writer.writerows(selected)

    cmd_counts = Counter(int(row["cmd_id"]) for row in selected)
    type_counts = Counter(
        (row["type_definition_index"], row["type_name"]) for row in selected
    )
    focus = {
        str(cmd_id): [row for row in selected if int(row["cmd_id"]) == cmd_id]
        for cmd_id in focus_cmd_ids
    }
    summary: dict[str, object] = {
        "source": str(input_csv),
        "anchor": {
            "cmd_id": anchor_cmd_id,
            "type_name": anchor_type_name,
            "get_cmd_id_rva": f"0x{anchor_rva:X}",
            "method_name": anchor_method_name,
        },
        "pattern": pattern,
        "row_count": len(selected),
        "unique_cmd_ids": len(cmd_counts),
        "unique_types": len(type_counts),
        "duplicate_cmd_ids": {str(key): value for key, value in cmd_counts.items() if value > 1},
        "duplicate_types": {
            f"{key[0]}:{key[1]}": value for key, value in type_counts.items() if value > 1
        },
        "focus": focus,
        "status": "getcmdid-static-candidate-graph",
        "notes": [
            "this graph is derived only from GetCmdId method identity and machine-code stub shape",
            "it is distinct from registry-candidate-graph artifacts built from metadata-usage joins",
        ],
    }
    summary_json.parent.mkdir(parents=True, exist_ok=True)
    summary_json.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return summary


def _rva(value: str) -> int:
    return int(value, 0)


def _cmd_ids(value: str) -> tuple[int, ...]:
    if not value.strip():
        return ()
    return tuple(int(part.strip(), 0) for part in value.split(",") if part.strip())


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.getcmdidgraph",
        description="Build a GetCmdId-method/stub-shape candidate graph from scanner output.",
    )
    parser.add_argument("input_csv", type=Path)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument("summary_json", type=Path)
    parser.add_argument("--anchor-cmd-id", type=int, required=True)
    parser.add_argument("--anchor-type", required=True)
    parser.add_argument("--anchor-rva", type=_rva, required=True)
    parser.add_argument("--pattern", default="mov-ax-imm16-ret")
    parser.add_argument("--focus", type=_cmd_ids, default=())
    args = parser.parse_args()

    result = build_getcmdid_candidate_graph(
        args.input_csv,
        args.output_csv,
        args.summary_json,
        anchor_cmd_id=args.anchor_cmd_id,
        anchor_type_name=args.anchor_type,
        anchor_rva=args.anchor_rva,
        pattern=args.pattern,
        focus_cmd_ids=args.focus,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
