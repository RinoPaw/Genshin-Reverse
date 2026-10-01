from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from genshinre.pe import PEImage


def parse_int(value: str | None) -> int | None:
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    try:
        return int(value, 0)
    except ValueError:
        return None


def main() -> None:
    p = argparse.ArgumentParser(description="Compare source-order layout of one owner's RPC submit callers and known handlers.")
    p.add_argument("exe", type=Path)
    p.add_argument("methods_csv", type=Path)
    p.add_argument("owner_type")
    p.add_argument("submit_rva", type=lambda x: int(x, 0))
    p.add_argument("output_json", type=Path)
    p.add_argument("--focus", action="append", default=[], help="label:rva")
    args = p.parse_args()

    all_methods = []
    owner_methods = []
    with args.methods_csv.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            rva = parse_int(row.get("rva"))
            if rva is None or rva <= 0:
                continue
            item = (rva, row)
            all_methods.append(item)
            if row.get("type_name") == args.owner_type:
                owner_methods.append(item)
    all_methods.sort(key=lambda x: x[0])
    owner_methods.sort(key=lambda x: x[0])
    all_rvas = [rva for rva, _ in all_methods]

    callers = []
    with PEImage(args.exe) as image:
        for rva, row in owner_methods:
            import bisect
            pos = bisect.bisect_right(all_rvas, rva)
            next_rva = all_rvas[pos] if pos < len(all_rvas) else rva + 0x4000
            size = min(max(next_rva - rva, 1), 0x4000)
            blob = image.read_rva(rva, size)
            offsets = []
            for off in range(0, max(0, len(blob) - 4)):
                if blob[off] != 0xE8:
                    continue
                disp = int.from_bytes(blob[off + 1:off + 5], "little", signed=True)
                target = rva + off + 5 + disp
                if target == args.submit_rva:
                    offsets.append(off)
            if offsets:
                callers.append({
                    "rva": f"0x{rva:X}",
                    "method_index": int(row.get("method_index") or 0),
                    "method_name": row.get("method_name", ""),
                    "submit_call_rvas": [f"0x{rva + off:X}" for off in offsets],
                    "parameter_start": row.get("parameter_start", ""),
                    "parameter_count": row.get("parameter_count", ""),
                })

    focuses = []
    for spec in args.focus:
        label, text = spec.split(":", 1)
        focus_rva = int(text, 0)
        exact = next((row for rva, row in owner_methods if rva == focus_rva), None)
        focus_index = int(exact.get("method_index") or 0) if exact else None
        before = [c for c in callers if int(c["rva"], 0) < focus_rva]
        after = [c for c in callers if int(c["rva"], 0) > focus_rva]
        prev = before[-1] if before else None
        nxt = after[0] if after else None
        item = {
            "label": label,
            "rva": f"0x{focus_rva:X}",
            "method_index": focus_index,
            "method_name": exact.get("method_name", "") if exact else "",
            "previous_submit_caller": prev,
            "next_submit_caller": nxt,
        }
        if focus_index is not None and prev is not None:
            item["method_index_delta_from_previous_submit"] = focus_index - int(prev["method_index"])
        if focus_index is not None and nxt is not None:
            item["method_index_delta_to_next_submit"] = int(nxt["method_index"]) - focus_index
        focuses.append(item)

    report = {
        "owner_type": args.owner_type,
        "submit_rva": f"0x{args.submit_rva:X}",
        "owner_method_count": len(owner_methods),
        "submit_caller_count": len(callers),
        "submit_callers": callers,
        "focus": focuses,
        "notes": [
            "direct E8 calls to the already-confirmed generic RPC submit are sender controls",
            "method-index distance is evaluated only as an intra-owner source-layout heuristic and must be validated across known Req/Rsp controls",
        ],
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("submit callers:", len(callers))
    for caller in callers:
        print(caller["method_index"], caller["rva"], caller["method_name"], caller["submit_call_rvas"])
    print("focus:")
    for item in focuses:
        print(item)


if __name__ == "__main__":
    main()
