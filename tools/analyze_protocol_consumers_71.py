from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def main() -> None:
    p = argparse.ArgumentParser(
        description="Find metadata methods that consume or return selected 7.1 protocol types."
    )
    p.add_argument("registry_csv", type=Path)
    p.add_argument("methods_csv", type=Path)
    p.add_argument("candidate_csv", type=Path)
    p.add_argument("output_json", type=Path)
    p.add_argument(
        "--control-cmd",
        action="append",
        default=[],
        help="Additional CmdId control (repeatable).",
    )
    args = p.parse_args()

    registry_rows = load_csv(args.registry_csv)
    registry = {int(r["cmd_id"], 0): r for r in registry_rows}
    candidate_ids = [int(r["cmd_id"], 0) for r in load_csv(args.candidate_csv)]
    control_ids = [int(x, 0) for x in args.control_cmd]
    focus_ids = list(dict.fromkeys(candidate_ids + control_ids))

    missing = [cmd for cmd in focus_ids if cmd not in registry]
    if missing:
        raise SystemExit(f"CmdIds missing from registry: {missing}")

    type_to_cmd = {
        registry[cmd]["type_name"]: cmd
        for cmd in focus_ids
        if registry[cmd].get("type_name")
    }
    refs: dict[int, list[dict[str, object]]] = {cmd: [] for cmd in focus_ids}

    with args.methods_csv.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            params = row.get("parameter_types", "") or ""
            ret = row.get("return_type", "") or ""
            if not params and not ret:
                continue
            declaring = row.get("type_name", "") or ""
            for type_name, cmd in type_to_cmd.items():
                in_params = type_name in params
                in_return = type_name == ret or type_name in ret
                if not in_params and not in_return:
                    continue
                refs[cmd].append(
                    {
                        "declaring_type": declaring,
                        "method_name": row.get("method_name", ""),
                        "method_rva": row.get("rva", ""),
                        "return_type": ret,
                        "parameter_types": params,
                        "parameter_count": row.get("parameter_count", ""),
                        "match_parameter": in_params,
                        "match_return": in_return,
                        "self_type": declaring == type_name,
                    }
                )

    rows = []
    candidate_set = set(candidate_ids)
    for cmd in focus_ids:
        reg = registry[cmd]
        all_refs = refs[cmd]
        external = [r for r in all_refs if not r["self_type"]]
        parameter_external = [r for r in external if r["match_parameter"]]
        return_external = [r for r in external if r["match_return"]]
        rows.append(
            {
                "cmd_id": cmd,
                "role": "candidate" if cmd in candidate_set else "control",
                "semantic_name": reg.get("semantic_name", ""),
                "type_name": reg.get("type_name", ""),
                "type_definition_index": reg.get("type_definition_index", ""),
                "type_slot_rva": reg.get("type_slot_rva", ""),
                "get_cmd_id_rva": reg.get("get_cmd_id_rva", ""),
                "registry_xref_count": reg.get("xref_count", ""),
                "registry_xref_method_count": reg.get("xref_method_count", ""),
                "reference_count": len(all_refs),
                "external_reference_count": len(external),
                "external_parameter_reference_count": len(parameter_external),
                "external_return_reference_count": len(return_external),
                "external_references": external,
            }
        )

    report = {
        "candidate_count": len(candidate_ids),
        "control_count": len(control_ids),
        "rows": rows,
        "notes": [
            "external metadata parameter references are handler/consumer leads, not semantic proof by themselves",
            "self-type protobuf CopyFrom/parser methods are excluded from external counts",
            "confirmed S2C and C2S controls should be compared before interpreting candidate reference patterns",
        ],
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("cmd role type external param return")
    for row in rows:
        print(
            row["cmd_id"], row["role"], row["type_name"],
            row["external_reference_count"],
            row["external_parameter_reference_count"],
            row["external_return_reference_count"],
        )
        for ref in row["external_references"][:20]:
            print("  ", ref["method_rva"], ref["declaring_type"], ref["method_name"],
                  "P" if ref["match_parameter"] else "", "R" if ref["match_return"] else "")


if __name__ == "__main__":
    main()
