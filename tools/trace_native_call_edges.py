from __future__ import annotations

import argparse
import bisect
import csv
import json
import struct
from collections import defaultdict
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM

from genshinre.pe import PEImage


def parse_rva(text: str) -> int:
    return int(text, 0)


def load_methods(path: Path):
    by_rva: dict[int, list[dict[str, str]]] = defaultdict(list)
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            try:
                rva = int(row.get("rva") or "0", 0)
            except ValueError:
                continue
            if rva > 0:
                by_rva[rva].append(row)
    starts = sorted(by_rva)
    return starts, by_rva


def compact_method(row: dict[str, str]) -> dict[str, object]:
    return {
        "method_index": row.get("method_index", ""),
        "type_name": row.get("type_name", ""),
        "method_name": row.get("method_name", ""),
        "parameter_count": row.get("parameter_count", ""),
        "parameter_types": row.get("parameter_types", ""),
        "return_type": row.get("return_type", ""),
        "type_definition_index": row.get("type_definition_index", ""),
    }


def owner_for(starts: list[int], by_rva: dict[int, list[dict[str, str]]], rva: int):
    i = bisect.bisect_right(starts, rva) - 1
    if i < 0:
        return None
    start = starts[i]
    end = starts[i + 1] if i + 1 < len(starts) else start + 0x10000
    if not (start <= rva < end):
        return None
    return {
        "rva": f"0x{start:X}",
        "end_rva": f"0x{end:X}",
        "size_to_next_method": end - start,
        "metadata_rows": [compact_method(row) for row in by_rva[start]],
    }


def direct_target(image_base: int, insn) -> int | None:
    if insn.mnemonic not in {"call", "jmp"}:
        return None
    for operand in insn.operands:
        if operand.type == X86_OP_IMM:
            value = int(operand.imm)
            return value - image_base if value >= image_base else value
    return None


def main() -> None:
    p = argparse.ArgumentParser(
        description="Trace direct native callers/callees for selected method RVAs."
    )
    p.add_argument("exe", type=Path)
    p.add_argument("methods_csv", type=Path)
    p.add_argument("output_json", type=Path)
    p.add_argument("--focus", action="append", default=[], help="LABEL:RVA, repeatable")
    p.add_argument("--max-body", type=lambda x: int(x, 0), default=0x8000)
    args = p.parse_args()

    if not args.focus:
        raise SystemExit("at least one --focus LABEL:RVA is required")
    focus = {}
    for item in args.focus:
        if ":" not in item:
            raise SystemExit(f"bad focus {item!r}")
        label, value = item.split(":", 1)
        focus[label] = parse_rva(value)

    starts, by_rva = load_methods(args.methods_csv)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    report = {
        "focus": {},
        "notes": [
            "Caller discovery first scans x86 E8 rel32 encodings in executable sections, then validates each hit by disassembling its decoded metadata owner.",
            "Direct callees/jumps are decoded from the selected method body and annotated with metadata owners where available.",
            "Indirect virtual/delegate calls are preserved in the full disassembly but are not resolved by this tool.",
        ],
    }

    with PEImage(args.exe) as image:
        image_base = image.image_base

        raw_sites: dict[int, list[int]] = {target: [] for target in focus.values()}
        for sec in image.sections:
            if not (sec.characteristics & 0x20000000):
                continue
            blob = image.read_rva(sec.virtual_address, sec.raw_size)
            pos = 0
            while True:
                pos = blob.find(b"\xE8", pos)
                if pos < 0:
                    break
                if pos + 5 <= len(blob):
                    rel = struct.unpack_from("<i", blob, pos + 1)[0]
                    call_rva = sec.virtual_address + pos
                    target = call_rva + 5 + rel
                    if target in raw_sites:
                        raw_sites[target].append(call_rva)
                pos += 1

        for label, target in focus.items():
            target_owner = owner_for(starts, by_rva, target)
            if target_owner is None:
                raise RuntimeError(f"focus {label} 0x{target:X} has no metadata owner")
            start = int(target_owner["rva"], 0)
            end = int(target_owner["end_rva"], 0)
            if end - start > args.max_body:
                end = start + args.max_body

            body = image.read_rva(start, end - start)
            disasm = []
            direct_edges = []
            for insn in md.disasm(body, image_base + start):
                irva = insn.address - image_base
                edge_target = direct_target(image_base, insn)
                row = {
                    "rva": f"0x{irva:X}",
                    "mnemonic": insn.mnemonic,
                    "op_str": insn.op_str,
                    "bytes": insn.bytes.hex(),
                }
                if edge_target is not None:
                    edge_owner = owner_for(starts, by_rva, edge_target)
                    row["direct_target_rva"] = f"0x{edge_target:X}"
                    row["direct_target_owner"] = edge_owner
                    direct_edges.append(
                        {
                            "site_rva": f"0x{irva:X}",
                            "kind": insn.mnemonic,
                            "target_rva": f"0x{edge_target:X}",
                            "target_owner": edge_owner,
                        }
                    )
                disasm.append(row)

            callers = []
            for site in raw_sites[target]:
                owner = owner_for(starts, by_rva, site)
                if owner is None:
                    continue
                caller_start = int(owner["rva"], 0)
                caller_end = min(int(owner["end_rva"], 0), caller_start + args.max_body)
                try:
                    caller_blob = image.read_rva(caller_start, caller_end - caller_start)
                except Exception:
                    continue
                insns = list(md.disasm(caller_blob, image_base + caller_start))
                exact_index = None
                for i, insn in enumerate(insns):
                    irva = insn.address - image_base
                    if irva != site:
                        continue
                    if insn.mnemonic != "call" or direct_target(image_base, insn) != target:
                        break
                    exact_index = i
                    break
                if exact_index is None:
                    continue
                lo = max(0, exact_index - 12)
                hi = min(len(insns), exact_index + 13)
                callers.append(
                    {
                        "call_site_rva": f"0x{site:X}",
                        "caller": owner,
                        "context": [
                            {
                                "rva": f"0x{x.address - image_base:X}",
                                "mnemonic": x.mnemonic,
                                "op_str": x.op_str,
                            }
                            for x in insns[lo:hi]
                        ],
                    }
                )

            report["focus"][label] = {
                "requested_rva": f"0x{target:X}",
                "owner": target_owner,
                "raw_e8_candidate_count": len(raw_sites[target]),
                "validated_direct_caller_count": len(callers),
                "direct_callers": callers,
                "direct_edges": direct_edges,
                "disassembly": disasm,
            }

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    for label, item in report["focus"].items():
        print("===", label, item["requested_rva"], "===")
        print("owner", item["owner"])
        print("validated direct callers", item["validated_direct_caller_count"])
        for caller in item["direct_callers"]:
            print(" caller", caller["call_site_rva"], caller["caller"])
        print("direct edges")
        for edge in item["direct_edges"]:
            if edge["kind"] == "call":
                print(" ", edge["site_rva"], "->", edge["target_rva"], edge["target_owner"])


if __name__ == "__main__":
    main()
