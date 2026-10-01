from __future__ import annotations

import argparse
import csv
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from genshinre.pe import PEImage

CONSTANTS = {
    "parameter_header_xor": 0x3E5D33E6,
    "method_key_mul": 0x3348BF73,
    "method_key_xor": 0x73758947,
    "method_key_add": 0x5C439E5B,
    "method_param_start_add": 0xF0A05526,
    "method_declaring_type_xor": 0x59244785,
    "field_key_mul1": 0x87DE,
    "field_key_xor": 0x59B1DB19,
    "field_key_mul2": 0x6CB83B74,
    "field_key_add": 0x540C1A0D,
}


def parse_methods(path: Path):
    methods = []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            text = (row.get("rva") or "").strip()
            if not text:
                continue
            try:
                rva = int(text, 0)
            except ValueError:
                continue
            methods.append((rva, row))
    methods.sort(key=lambda x: x[0])
    return methods


def owner_for(methods, rva: int):
    import bisect
    starts = [x[0] for x in methods]
    i = bisect.bisect_right(starts, rva) - 1
    if i < 0:
        return None
    start, row = methods[i]
    end = starts[i + 1] if i + 1 < len(starts) else start + 0x10000
    if not (start <= rva < end):
        return None
    return {
        "start_rva": f"0x{start:X}",
        "offset": rva - start,
        "type_name": row.get("type_name", ""),
        "method_name": row.get("method_name", ""),
        "method_index": row.get("method_index", ""),
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Locate exact 7.1 MHY metadata decoder constants in native code.")
    p.add_argument("exe", type=Path)
    p.add_argument("methods_csv", type=Path)
    p.add_argument("output_json", type=Path)
    args = p.parse_args()

    methods = parse_methods(args.methods_csv)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    report = {"constants": {}, "notes": []}

    with PEImage(args.exe) as image:
        for name, value in CONSTANTS.items():
            needle = struct.pack("<I", value)
            hits = []
            for section in image.sections:
                blob = image.read_rva(section.virtual_address, section.raw_size)
                if not blob:
                    continue
                pos = 0
                while True:
                    pos = blob.find(needle, pos)
                    if pos < 0:
                        break
                    rva = section.virtual_address + pos
                    context_start = max(section.virtual_address, rva - 96)
                    context = image.read_rva(context_start, 320)
                    disasm = []
                    for insn in md.disasm(context, image.image_base + context_start):
                        irva = insn.address - image.image_base
                        disasm.append({
                            "rva": f"0x{irva:X}",
                            "mnemonic": insn.mnemonic,
                            "op_str": insn.op_str,
                            "covers_constant": irva <= rva < irva + insn.size,
                        })
                    hits.append({
                        "rva": f"0x{rva:X}",
                        "section": section.name,
                        "executable": bool(section.characteristics & 0x20000000),
                        "owner": owner_for(methods, rva),
                        "context_start_rva": f"0x{context_start:X}",
                        "context_hex": context.hex(),
                        "disasm": disasm,
                    })
                    pos += 1
            report["constants"][name] = {
                "value": f"0x{value:08X}",
                "hit_count": len(hits),
                "hits": hits,
            }

    report["notes"] = [
        "hits are raw little-endian immediate byte matches; executable hits are leads, not automatically instruction operands",
        "covers_constant marks the instruction Capstone decoded across the matched byte offset from a nearby synchronization point",
        "known method/field constants are controls for locating the metadata decryption neighborhood before inferring parameter formulas",
    ]
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    for name, item in report["constants"].items():
        print(name, item["value"], "hits=", item["hit_count"])
        for hit in item["hits"][:10]:
            print(" ", hit["rva"], hit["section"], "exec=" + str(hit["executable"]), hit["owner"])
            around = [x for x in hit["disasm"] if x["covers_constant"]]
            for insn in around:
                print("    ", insn["rva"], insn["mnemonic"], insn["op_str"])


if __name__ == "__main__":
    main()
