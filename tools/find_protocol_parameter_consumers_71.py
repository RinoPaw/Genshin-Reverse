from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def parse_params(value: str) -> list[str]:
    text = (value or "").strip()
    if not text:
        return []
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return [part.strip() for part in text.split("|") if part.strip()]
    return [str(item) for item in value] if isinstance(value, list) else []


def main() -> None:
    p = argparse.ArgumentParser(description="Find external method consumers of selected 7.1 protocol types.")
    p.add_argument("registry_csv", type=Path)
    p.add_argument("methods_csv", type=Path)
    p.add_argument("candidate_csv", type=Path)
    p.add_argument("output_json", type=Path)
    p.add_argument("--control-cmd", action="append", default=[])
    args = p.parse_args()

    registry_rows = load_csv(args.registry_csv)
    registry = {int(r["cmd_id"], 0): r for r in registry_rows}
    candidate_ids = [int(r["cmd_id"], 0) for r in load_csv(args.candidate_csv)]
    control_ids = [int(value, 0) for value in args.control_cmd]
    focus_ids = list(dict.fromkeys(candidate_ids + control_ids))
    candidate_set = set(candidate_ids)

    missing = [cmd for cmd in focus_ids if cmd not in registry]
    if missing:
        raise SystemExit(f"CmdIds missing from registry: {missing}")

    type_to_cmd = {
        registry[cmd]["type_name"]: cmd
        for cmd in focus_ids
        if registry[cmd].get("type_name")
    }
    consumers: dict[int, list[dict[str, object]]] = {cmd: [] for cmd in focus_ids}

    with args.methods_csv.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            declaring_type = row.get("type_name", "") or ""
            params = parse_params(row.get("parameter_types", "") or "")
            for ordinal, parameter_type in enumerate(params):
                cmd = type_to_cmd.get(parameter_type)
                if cmd is None or declaring_type == parameter_type:
                    continue
                consumers[cmd].append(
                    {
                        "declaring_type": declaring_type,
                        "method_name": row.get("method_name", ""),
                        "method_rva": row.get("rva", ""),
                        "method_index": row.get("method_index", ""),
                        "type_definition_index": row.get("type_definition_index", ""),
                        "parameter_ordinal": ordinal,
                        "parameter_types": params,
                        "parameter_start": row.get("parameter_start", ""),
                        "parameter_count": row.get("parameter_count", ""),
                    }
                )

    rows = []
    for cmd in focus_ids:
        reg = registry[cmd]
        refs = consumers[cmd]
        owner_types = sorted({str(ref["declaring_type"]) for ref in refs})
        rows.append(
            {
                "cmd_id": cmd,
                "role": "candidate" if cmd in candidate_set else "control",
                "semantic_name": reg.get("semantic_name", ""),
                "type_name": reg.get("type_name", ""),
                "external_consumer_count": len(refs),
                "external_consumer_type_count": len(owner_types),
                "external_consumer_types": owner_types,
                "external_consumers": refs,
            }
        )

    report = {
        "candidate_count": len(candidate_ids),
        "control_count": len(control_ids),
        "candidates_with_external_consumers": sum(
            row["role"] == "candidate" and int(row["external_consumer_count"]) > 0 for row in rows
        ),
        "rows": rows,
        "notes": [
            "parameter types come from the exact current 7.1 MHY parameter decoder",
            "methods declared on the protobuf type itself are excluded",
            "an external parameter consumer is a positive handler/consumer lead; semantic identity still requires context",
        ],
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("cmd role type consumers owner-types")
    for row in rows:
        print(
            row["cmd_id"], row["role"], row["type_name"], row["external_consumer_count"],
            "|".join(row["external_consumer_types"]),
        )
        for ref in row["external_consumers"][:24]:
            print(
                "  ", ref["method_rva"],
                f"{ref['declaring_type']}.{ref['method_name']}",
                "param#", ref["parameter_ordinal"], ref["parameter_types"],
            )


if __name__ == "__main__":
    main()
