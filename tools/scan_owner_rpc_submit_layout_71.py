from __future__ import annotations

import argparse
import bisect
import csv
import json
from collections import Counter
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
    p = argparse.ArgumentParser(description="Compare one owner's RPC submit callers, exact request type-slot references, and known handlers.")
    p.add_argument("exe", type=Path)
    p.add_argument("methods_csv", type=Path)
    p.add_argument("registry_csv", type=Path)
    p.add_argument("owner_type")
    p.add_argument("submit_rva", type=lambda x: int(x, 0))
    p.add_argument("output_json", type=Path)
    p.add_argument("--focus", action="append", default=[], help="label:rva")
    args = p.parse_args()

    try:
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs
        from capstone.x86 import X86_OP_MEM, X86_REG_RIP
    except ImportError as exc:
        raise RuntimeError("scan_owner_rpc_submit_layout_71 requires capstone") from exc

    registry_slots: dict[int, dict[str, object]] = {}
    with args.registry_csv.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            slot = parse_int(row.get("type_slot_rva"))
            cmd_id = parse_int(row.get("cmd_id"))
            if slot is None or cmd_id is None:
                continue
            registry_slots[slot] = {
                "cmd_id": cmd_id,
                "type_name": row.get("type_name", ""),
                "semantic_name": row.get("semantic_name", ""),
                "registry_index": parse_int(row.get("index")),
                "type_slot_rva": f"0x{slot:X}",
            }

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

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    callers = []
    with PEImage(args.exe) as image:
        for rva, row in owner_methods:
            pos = bisect.bisect_right(all_rvas, rva)
            next_rva = all_rvas[pos] if pos < len(all_rvas) else rva + 0x4000
            size = min(max(next_rva - rva, 1), 0x4000)
            blob = image.read_rva(rva, size)
            submit_offsets = []
            for off in range(0, max(0, len(blob) - 4)):
                if blob[off] != 0xE8:
                    continue
                disp = int.from_bytes(blob[off + 1:off + 5], "little", signed=True)
                target = rva + off + 5 + disp
                if target == args.submit_rva:
                    submit_offsets.append(off)
            if not submit_offsets:
                continue

            first_submit_rva = rva + min(submit_offsets)
            slot_hits = []
            slot_counts: Counter[int] = Counter()
            for insn in md.disasm(blob, rva):
                if insn.address > first_submit_rva:
                    break
                for operand in insn.operands:
                    if operand.type != X86_OP_MEM or operand.mem.base != X86_REG_RIP:
                        continue
                    target = insn.address + insn.size + operand.mem.disp
                    protocol = registry_slots.get(target)
                    if protocol is None:
                        continue
                    slot_counts[target] += 1
                    slot_hits.append({
                        "instruction_rva": f"0x{insn.address:X}",
                        "mnemonic": insn.mnemonic,
                        "op_str": insn.op_str,
                        **protocol,
                    })

            protocol_refs = []
            for slot, count in sorted(slot_counts.items(), key=lambda item: (-item[1], item[0])):
                protocol_refs.append({**registry_slots[slot], "reference_count_before_submit": count})

            callers.append({
                "rva": f"0x{rva:X}",
                "method_index": int(row.get("method_index") or 0),
                "method_name": row.get("method_name", ""),
                "submit_call_rvas": [f"0x{rva + off:X}" for off in submit_offsets],
                "parameter_start": row.get("parameter_start", ""),
                "parameter_count": row.get("parameter_count", ""),
                "parameter_types": row.get("parameter_types", ""),
                "protocol_type_slot_refs_before_submit": protocol_refs,
                "protocol_type_slot_hit_instructions": slot_hits,
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
        "verified_registry_slot_count": len(registry_slots),
        "owner_method_count": len(owner_methods),
        "submit_caller_count": len(callers),
        "submit_callers": callers,
        "focus": focuses,
        "notes": [
            "direct E8 calls to the already-confirmed generic RPC submit are sender controls",
            "RIP-relative references to verified registry type slots before the submit call identify protocol classes used by each sender",
            "for UnlockTransPointReq the known sender reference resolves independently to slot 0x057E6498 / CmdId 9369 and serves as the anchor",
            "method/RVA distance remains an intra-owner layout heuristic and is interpreted only after request identity is recovered",
        ],
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("submit callers:", len(callers))
    for caller in callers:
        refs = [f"{ref['cmd_id']}:{ref['type_name']}" for ref in caller["protocol_type_slot_refs_before_submit"]]
        print(caller["method_index"], caller["rva"], caller["method_name"], caller["submit_call_rvas"], "refs=", "|".join(refs))
    print("focus:")
    for item in focuses:
        print(item)


if __name__ == "__main__":
    main()
