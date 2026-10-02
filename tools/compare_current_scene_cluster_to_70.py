from __future__ import annotations

import argparse
import bisect
import csv
import difflib
import json
import re
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

from genshinre.pe import PEImage


def token(insn) -> str:
    out = [insn.mnemonic]
    for op in insn.operands:
        if op.type == X86_OP_REG:
            out.append("R")
        elif op.type == X86_OP_IMM:
            v = int(op.imm)
            if insn.mnemonic == "call" or insn.mnemonic.startswith("j"):
                out.append("T")
            elif -0x400 <= v <= 0x400:
                out.append(f"I{v:+#x}")
            else:
                out.append("I")
        elif op.type == X86_OP_MEM:
            m = op.mem
            if m.base == X86_REG_RIP:
                out.append("MRIP")
            elif -0x800 <= int(m.disp) <= 0x800:
                out.append(f"M{int(m.disp):+#x}")
            else:
                out.append("M")
        else:
            out.append("O")
    return ":".join(out)


def fingerprint(image: PEImage, md: Cs, start: int, end: int):
    rows = list(md.disasm(image.read_rva(start, end - start), image.image_base + start))
    if not rows:
        return None
    return {
        "tokens": [token(i) for i in rows],
        "mnemonics": [i.mnemonic for i in rows],
        "size": end - start,
        "instruction_count": len(rows),
    }


def similarity(a, b):
    tr = difflib.SequenceMatcher(None, a["tokens"], b["tokens"], autojunk=False).ratio()
    mr = difflib.SequenceMatcher(None, a["mnemonics"], b["mnemonics"], autojunk=False).ratio()
    sr = min(a["size"], b["size"]) / max(a["size"], b["size"])
    return 0.65 * tr + 0.25 * mr + 0.10 * sr, tr, mr, sr


def old_owner_and_rvas(path: Path, owner_name: str):
    owner = None
    rvas: set[int] = set()
    rva_re = re.compile(r'"rva":(\d+)')
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if '"rva":' in line:
                for v in rva_re.findall(line):
                    n = int(v)
                    if n > 0:
                        rvas.add(n)
            if owner is None and f'"name":"{owner_name}"' in line:
                obj, _ = json.JSONDecoder().raw_decode(line.strip())
                if obj.get("name") == owner_name:
                    owner = obj
    if owner is None:
        raise RuntimeError(f"owner {owner_name} not found")
    return owner, sorted(rvas)


def current_methods(path: Path, owner_name: str):
    all_rows = []
    owner_rows = []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            try:
                rva = int(row.get("rva") or "0", 0)
            except ValueError:
                continue
            if rva <= 0:
                continue
            all_rows.append((rva, row))
            if row.get("type_name") == owner_name:
                owner_rows.append((rva, row))
    all_rows.sort(key=lambda x: x[0])
    owner_rows.sort(key=lambda x: int(x[1].get("method_index") or 0))
    return all_rows, owner_rows


def end_for(start: int, starts: list[int], max_size: int = 0x3000):
    i = bisect.bisect_right(starts, start)
    if i >= len(starts):
        return None
    end = starts[i]
    if end <= start or end - start > max_size:
        return None
    return end


def main() -> None:
    p = argparse.ArgumentParser(description="Map the current UnlockTransPoint scene cluster back to the 7.0 scene controller by native fingerprints.")
    p.add_argument("exe70", type=Path)
    p.add_argument("dump70", type=Path)
    p.add_argument("exe71", type=Path)
    p.add_argument("methods71", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--old-owner", default="KGCKOFPFBLA")
    p.add_argument("--new-owner", default="KLLNGCPBLMM")
    p.add_argument("--start-rva", default="0xF0452B0")
    p.add_argument("--end-rva", default="0xF046C00")
    args = p.parse_args()

    old_owner, old_starts = old_owner_and_rvas(args.dump70, args.old_owner)
    new_all, new_owner = current_methods(args.methods71, args.new_owner)
    new_starts = [r for r, _ in new_all]
    lo = int(args.start_rva, 0)
    hi = int(args.end_rva, 0)

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    old_items = []
    with PEImage(args.exe70) as image:
        for pos, m in enumerate(old_owner.get("methods", [])):
            start = int(m.get("rva") or 0)
            if start <= 0:
                continue
            end = end_for(start, old_starts)
            if end is None:
                continue
            fp = fingerprint(image, md, start, end)
            if fp:
                old_items.append((pos, m, start, fp))

    new_items = []
    with PEImage(args.exe71) as image:
        for pos, (start, row) in enumerate(new_owner):
            if not (lo <= start < hi):
                continue
            end = end_for(start, new_starts)
            if end is None:
                continue
            fp = fingerprint(image, md, start, end)
            if fp:
                new_items.append((pos, row, start, fp))

    report_rows = []
    for new_pos, row, start, nfp in new_items:
        matches = []
        for old_pos, old_method, old_start, ofp in old_items:
            score, tr, mr, sr = similarity(nfp, ofp)
            matches.append({
                "score": score,
                "token_ratio": tr,
                "mnemonic_ratio": mr,
                "size_ratio": sr,
                "old_owner_position": old_pos,
                "old_method_index": old_method.get("idx"),
                "old_method_name": old_method.get("name"),
                "old_rva": f"0x{old_start:X}",
                "old_size": ofp["size"],
                "old_parameters": old_method.get("params") or [],
                "old_return_type": old_method.get("ret", ""),
            })
        matches.sort(key=lambda x: x["score"], reverse=True)
        report_rows.append({
            "new_owner_position": new_pos,
            "method_index": int(row.get("method_index") or 0),
            "method_name": row.get("method_name", ""),
            "rva": f"0x{start:X}",
            "size": nfp["size"],
            "parameter_types": row.get("parameter_types", ""),
            "top_old_matches": matches[:10],
        })

    result = {
        "old_owner": args.old_owner,
        "new_owner": args.new_owner,
        "current_range": [f"0x{lo:X}", f"0x{hi:X}"],
        "rows": report_rows,
        "notes": [
            "This is the inverse of the sender fingerprint probe: every current scene-cluster method is matched against all historical scene-controller methods.",
            "Generic ack handlers are expected to have ties; large non-generic methods with an isolated top match are the useful anchors.",
            "Use multiple coherent anchors before assigning semantic identity to either response candidate.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    for row in report_rows:
        print(row["rva"], row["method_name"], row["parameter_types"])
        for m in row["top_old_matches"][:3]:
            print("  ", f"{m['score']:.4f}", m["old_rva"], m["old_method_name"], "pos", m["old_owner_position"], m["old_parameters"])


if __name__ == "__main__":
    main()
