from __future__ import annotations

import argparse
import bisect
import csv
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

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
        "offset": rva - start,
        "type_name": row.get("type_name", ""),
        "method_name": row.get("method_name", ""),
        "method_index": row.get("method_index", ""),
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Trace native references to selected 7.1 protocol delegate-slot displacements.")
    p.add_argument("exe", type=Path)
    p.add_argument("methods_csv", type=Path)
    p.add_argument("output_json", type=Path)
    p.add_argument("--slot", action="append", required=True, help="slot displacement such as 0x4b2a90")
    args = p.parse_args()

    methods = load_methods(args.methods_csv)
    starts = [item[0] for item in methods]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    slots = [int(value, 0) for value in args.slot]
    report = {"slots": {}, "notes": []}

    with PEImage(args.exe) as image:
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
                    hits.append({
                        "raw_match_rva": f"0x{raw_rva:X}",
                        "owner": owner_for(methods, starts, raw_rva),
                        "instructions": insns,
                    })
                    pos += 1
            report["slots"][f"0x{slot:X}"] = {"hit_count": len(hits), "hits": hits}

    report["notes"] = [
        "raw little-endian displacement matches are leads; covers_slot_bytes identifies the decoded instruction containing the slot bytes",
        "look for references outside the candidate handler itself to locate delegate/static initialization and dispatch binding",
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


if __name__ == "__main__":
    main()
