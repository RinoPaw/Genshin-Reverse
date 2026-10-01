from __future__ import annotations

import argparse
import bisect
import csv
import json
from pathlib import Path

from genshinre.pe import PEImage


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def parse_int(text: str | None) -> int | None:
    if text is None:
        return None
    text = text.strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def main() -> None:
    p = argparse.ArgumentParser(
        description="Scan direct native E8 callers of methods declared on selected 7.1 protocol types."
    )
    p.add_argument("exe", type=Path)
    p.add_argument("registry_csv", type=Path)
    p.add_argument("methods_csv", type=Path)
    p.add_argument("candidate_csv", type=Path)
    p.add_argument("output_json", type=Path)
    p.add_argument("--control-cmd", action="append", default=[])
    args = p.parse_args()

    registry_rows = load_csv(args.registry_csv)
    registry = {int(r["cmd_id"], 0): r for r in registry_rows}
    candidate_ids = [int(r["cmd_id"], 0) for r in load_csv(args.candidate_csv)]
    control_ids = [int(x, 0) for x in args.control_cmd]
    focus_ids = list(dict.fromkeys(candidate_ids + control_ids))

    missing = [cmd for cmd in focus_ids if cmd not in registry]
    if missing:
        raise SystemExit(f"CmdIds missing from registry: {missing}")

    focus_type_to_cmd = {
        registry[cmd]["type_name"]: cmd
        for cmd in focus_ids
        if registry[cmd].get("type_name")
    }

    methods: list[tuple[int, dict[str, str]]] = []
    target_methods: dict[int, dict[str, object]] = {}
    with args.methods_csv.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            rva = parse_int(row.get("rva"))
            if rva is None or rva <= 0:
                continue
            methods.append((rva, row))
            cmd = focus_type_to_cmd.get(row.get("type_name", ""))
            if cmd is not None:
                target_methods[rva] = {
                    "cmd_id": cmd,
                    "type_name": row.get("type_name", ""),
                    "method_name": row.get("method_name", ""),
                    "method_index": row.get("method_index", ""),
                    "target_rva": f"0x{rva:X}",
                }

    methods.sort(key=lambda x: x[0])
    starts = [rva for rva, _ in methods]

    def owner_for(rva: int) -> dict[str, object] | None:
        i = bisect.bisect_right(starts, rva) - 1
        if i < 0:
            return None
        start, row = methods[i]
        end = starts[i + 1] if i + 1 < len(starts) else start + 0x10000
        if not (start <= rva < end):
            return None
        return {
            "method_rva": f"0x{start:X}",
            "offset": rva - start,
            "type_name": row.get("type_name", ""),
            "method_name": row.get("method_name", ""),
            "method_index": row.get("method_index", ""),
            "parameter_start": row.get("parameter_start", ""),
            "parameter_count": row.get("parameter_count", ""),
        }

    by_cmd: dict[int, list[dict[str, object]]] = {cmd: [] for cmd in focus_ids}
    with PEImage(args.exe) as image:
        for section in image.sections:
            if not (section.characteristics & 0x20000000):
                continue
            blob = image.read_rva(section.virtual_address, section.raw_size)
            if not blob:
                continue
            pos = 0
            while True:
                pos = blob.find(b"\xE8", pos)
                if pos < 0 or pos + 5 > len(blob):
                    break
                call_rva = section.virtual_address + pos
                disp = int.from_bytes(blob[pos + 1 : pos + 5], "little", signed=True)
                target_rva = call_rva + 5 + disp
                target = target_methods.get(target_rva)
                if target is not None:
                    owner = owner_for(call_rva)
                    if owner is not None:
                        by_cmd[int(target["cmd_id"])].append(
                            {
                                "call_rva": f"0x{call_rva:X}",
                                "caller": owner,
                                "target": target,
                                "external_type": owner["type_name"] != target["type_name"],
                            }
                        )
                pos += 1

    rows = []
    candidate_set = set(candidate_ids)
    for cmd in focus_ids:
        reg = registry[cmd]
        calls = by_cmd[cmd]
        external = [x for x in calls if x["external_type"]]
        caller_types = sorted({str(x["caller"]["type_name"]) for x in external})
        rows.append(
            {
                "cmd_id": cmd,
                "role": "candidate" if cmd in candidate_set else "control",
                "semantic_name": reg.get("semantic_name", ""),
                "type_name": reg.get("type_name", ""),
                "target_method_count": sum(
                    1 for item in target_methods.values() if int(item["cmd_id"]) == cmd
                ),
                "direct_call_count": len(calls),
                "external_direct_call_count": len(external),
                "external_caller_types": caller_types,
                "external_calls": external,
            }
        )

    report = {
        "sample": "7.1.0-global/windows-x64",
        "candidate_count": len(candidate_ids),
        "control_count": len(control_ids),
        "target_method_count": len(target_methods),
        "rows": rows,
        "notes": [
            "direct E8 callers are a consumer lead; virtual/interface/indirect calls are outside this probe",
            "caller ownership is assigned from the nearest decoded metadata method start",
            "confirmed handler controls must succeed before absence of calls is used as negative evidence",
        ],
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("cmd role type targets calls external caller-types")
    for row in rows:
        print(
            row["cmd_id"], row["role"], row["type_name"], row["target_method_count"],
            row["direct_call_count"], row["external_direct_call_count"],
            "|".join(row["external_caller_types"]),
        )
        for call in row["external_calls"][:12]:
            caller = call["caller"]
            target = call["target"]
            print(
                "  ", call["call_rva"],
                f"{caller['type_name']}.{caller['method_name']}",
                "->", f"{target['type_name']}.{target['method_name']}", target["target_rva"],
            )


if __name__ == "__main__":
    main()
