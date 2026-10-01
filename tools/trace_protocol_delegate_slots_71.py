from __future__ import annotations

import argparse
import bisect
import csv
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

from genshinre.pe import PEImage


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


def load_methods(path: Path):
    rows = []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            rva = parse_int(row.get("rva"))
            if rva is not None and rva > 0:
                rows.append((rva, row))
    rows.sort(key=lambda item: item[0])
    return rows


def owner_for(methods, starts, rva: int):
    i = bisect.bisect_right(starts, rva) - 1
    if i < 0:
        return None
    start, row = methods[i]
    end = methods[i + 1][0] if i + 1 < len(methods) else start + 0x10000
    if not (start <= rva < end):
        return None
    return {
        "rva": f"0x{start:X}",
        "end_rva": f"0x{end:X}",
        "offset": rva - start,
        "type_name": row.get("type_name", ""),
        "method_name": row.get("method_name", ""),
        "method_index": row.get("method_index", ""),
    }


def method_context(image: PEImage, md: Cs, owner: dict[str, object] | None, xref_rva: int) -> list[dict[str, object]]:
    if not owner:
        return []
    start = int(str(owner["rva"]), 0)
    end = int(str(owner["end_rva"]), 0)
    # Start at the decoded method boundary so instruction alignment is trustworthy.
    read_end = min(end, xref_rva + 0x100)
    if read_end <= start or read_end - start > 0x8000:
        return []
    blob = image.read_rva(start, read_end - start)
    rows = []
    for insn in md.disasm(blob, image.image_base + start):
        irva = insn.address - image.image_base
        if xref_rva - 0x80 <= irva <= xref_rva + 0x80:
            rows.append({
                "rva": f"0x{irva:X}",
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": insn.bytes.hex(),
                "is_xref": irva == xref_rva,
            })
        if irva > xref_rva + 0x80:
            break
    return rows


def main() -> None:
    p = argparse.ArgumentParser(description="Trace native references to selected 7.1 protocol delegate-slot displacements and their handler methods.")
    p.add_argument("exe", type=Path)
    p.add_argument("methods_csv", type=Path)
    p.add_argument("output_json", type=Path)
    p.add_argument("--slot", action="append", required=True, help="slot displacement such as 0x4b2a90")
    args = p.parse_args()

    methods = load_methods(args.methods_csv)
    starts = [item[0] for item in methods]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    slots = [int(value, 0) for value in args.slot]
    report = {"slots": {}, "handler_pointer_xrefs": {}, "notes": []}

    with PEImage(args.exe) as image:
        handler_rvas: set[int] = set()
        for slot in slots:
            needle = struct.pack("<I", slot & 0xFFFFFFFF)
            hits = []
            for section in image.sections:
                if not (section.characteristics & 0x20000000):
                    continue
                blob = image.read_rva(section.virtual_address, section.raw_size)
                pos = 0
                while True:
                    pos = blob.find(needle, pos)
                    if pos < 0:
                        break
                    raw_rva = section.virtual_address + pos
                    start = max(section.virtual_address, raw_rva - 48)
                    context = image.read_rva(start, 160)
                    insns = []
                    for insn in md.disasm(context, image.image_base + start):
                        irva = insn.address - image.image_base
                        covers = irva <= raw_rva < irva + insn.size
                        if covers or abs(irva - raw_rva) <= 24:
                            insns.append({
                                "rva": f"0x{irva:X}",
                                "mnemonic": insn.mnemonic,
                                "op_str": insn.op_str,
                                "covers_slot_bytes": covers,
                            })
                    owner = owner_for(methods, starts, raw_rva)
                    if owner and any(item["covers_slot_bytes"] for item in insns):
                        handler_rvas.add(int(str(owner["rva"]), 0))
                    hits.append({
                        "raw_match_rva": f"0x{raw_rva:X}",
                        "owner": owner,
                        "instructions": insns,
                    })
                    pos += 1
            report["slots"][f"0x{slot:X}"] = {"hit_count": len(hits), "hits": hits}

        # A response-handler method is commonly materialized as a native function pointer
        # when the IL2CPP client builds delegates or registers callbacks. Direct E8 caller
        # scans do not see those bindings, so recover RIP-relative/absolute code references.
        pointer_hits: dict[int, list[dict[str, object]]] = {rva: [] for rva in sorted(handler_rvas)}
        target_abs = {image.image_base + rva: rva for rva in handler_rvas}
        for section in image.sections:
            if not (section.characteristics & 0x20000000):
                continue
            blob = image.read_rva(section.virtual_address, section.raw_size)
            for insn in md.disasm(blob, image.image_base + section.virtual_address):
                matched: set[int] = set()
                for operand in insn.operands:
                    if operand.type == X86_OP_IMM:
                        target = target_abs.get(int(operand.imm))
                        if target is not None:
                            matched.add(target)
                    elif operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                        effective = insn.address + insn.size + operand.mem.disp
                        target = target_abs.get(int(effective))
                        if target is not None:
                            matched.add(target)
                if not matched:
                    continue
                irva = insn.address - image.image_base
                owner = owner_for(methods, starts, irva)
                for target in matched:
                    pointer_hits[target].append({
                        "xref_rva": f"0x{irva:X}",
                        "mnemonic": insn.mnemonic,
                        "op_str": insn.op_str,
                        "bytes": insn.bytes.hex(),
                        "owner": owner,
                    })

        for target, hits in pointer_hits.items():
            enriched = []
            for hit in hits:
                item = dict(hit)
                item["context"] = method_context(image, md, hit.get("owner"), int(str(hit["xref_rva"]), 0))
                enriched.append(item)
            target_owner = owner_for(methods, starts, target)
            report["handler_pointer_xrefs"][f"0x{target:X}"] = {
                "handler": target_owner,
                "xref_count": len(enriched),
                "xrefs": enriched,
            }

    report["notes"] = [
        "raw little-endian displacement matches are leads; covers_slot_bytes identifies the decoded instruction containing the slot bytes",
        "the owning method of a decoded delegate-slot access is treated as the handler whose function-pointer xrefs should be traced",
        "handler_pointer_xrefs includes RIP-relative and absolute native code references; these can reveal delegate construction or callback registration that direct E8 caller scans miss",
        "xref context starts at a decoded metadata method boundary to avoid false instruction alignment",
    ]
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for slot, item in report["slots"].items():
        print(slot, "hits=", item["hit_count"])
        for hit in item["hits"]:
            owner = hit["owner"] or {}
            print(" ", hit["raw_match_rva"], owner.get("type_name"), owner.get("method_name"), owner.get("method_index"))
            for insn in hit["instructions"]:
                if insn["covers_slot_bytes"]:
                    print("    ", insn["rva"], insn["mnemonic"], insn["op_str"])
    print("handler pointer xrefs:")
    for target, item in report["handler_pointer_xrefs"].items():
        handler = item.get("handler") or {}
        print(target, handler.get("type_name"), handler.get("method_name"), "xrefs=", item["xref_count"])
        for hit in item["xrefs"]:
            owner = hit.get("owner") or {}
            print(" ", hit["xref_rva"], hit["mnemonic"], hit["op_str"], "owner=", owner.get("type_name"), owner.get("method_name"))


if __name__ == "__main__":
    main()
