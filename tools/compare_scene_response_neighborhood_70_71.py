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


def _token(insn) -> str:
    parts = [insn.mnemonic]
    for op in insn.operands:
        if op.type == X86_OP_REG:
            parts.append("R")
        elif op.type == X86_OP_IMM:
            value = int(op.imm)
            if insn.mnemonic == "call" or insn.mnemonic.startswith("j"):
                parts.append("T")
            elif -0x400 <= value <= 0x400:
                parts.append(f"I{value:+#x}")
            else:
                parts.append("I")
        elif op.type == X86_OP_MEM:
            mem = op.mem
            if mem.base == X86_REG_RIP:
                parts.append("MRIP")
            elif -0x800 <= int(mem.disp) <= 0x800:
                parts.append(f"M{int(mem.disp):+#x}")
            else:
                parts.append("M")
        else:
            parts.append("O")
    return ":".join(parts)


def _read_old_owner(dump_json: Path, owner_name: str):
    owner = None
    all_rvas: set[int] = set()
    rva_re = re.compile(r'"rva":(\d+)')
    with dump_json.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if '"rva":' in line:
                for value in rva_re.findall(line):
                    rva = int(value)
                    if rva > 0:
                        all_rvas.add(rva)
            if owner is None and f'"name":"{owner_name}"' in line:
                obj, _ = json.JSONDecoder().raw_decode(line.strip())
                if obj.get("name") == owner_name:
                    owner = obj
    if owner is None:
        raise RuntimeError(f"historical owner {owner_name} not found")
    return owner, sorted(all_rvas)


def _read_current_methods(methods_csv: Path, owner_name: str):
    all_rows = []
    owner_rows = []
    with methods_csv.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            try:
                rva = int(row.get("rva") or "0", 0)
            except ValueError:
                continue
            if rva <= 0:
                continue
            item = (rva, row)
            all_rows.append(item)
            if row.get("type_name") == owner_name:
                owner_rows.append(item)
    all_rows.sort(key=lambda x: x[0])
    owner_rows.sort(key=lambda x: int(x[1].get("method_index") or 0))
    return all_rows, owner_rows


def _end_for(start: int, starts: list[int], max_size: int = 0x3000) -> int | None:
    i = bisect.bisect_right(starts, start)
    if i >= len(starts):
        return None
    end = starts[i]
    if end <= start or end - start > max_size:
        return None
    return end


def _fingerprint(image: PEImage, md: Cs, start: int, end: int):
    blob = image.read_rva(start, end - start)
    tokens = []
    mnemonics = []
    for insn in md.disasm(blob, image.image_base + start):
        tokens.append(_token(insn))
        mnemonics.append(insn.mnemonic)
    if not tokens:
        return None
    return {
        "tokens": tokens,
        "mnemonics": mnemonics,
        "size": end - start,
        "instruction_count": len(tokens),
    }


def _similarity(a, b) -> dict[str, float]:
    token_ratio = difflib.SequenceMatcher(None, a["tokens"], b["tokens"], autojunk=False).ratio()
    mnemonic_ratio = difflib.SequenceMatcher(None, a["mnemonics"], b["mnemonics"], autojunk=False).ratio()
    size_ratio = min(a["size"], b["size"]) / max(a["size"], b["size"])
    score = token_ratio * 0.65 + mnemonic_ratio * 0.25 + size_ratio * 0.10
    return {
        "score": score,
        "token_ratio": token_ratio,
        "mnemonic_ratio": mnemonic_ratio,
        "size_ratio": size_ratio,
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Cross-version native neighborhood alignment for the scene UnlockTransPointRsp handler.")
    p.add_argument("exe70", type=Path)
    p.add_argument("dump70", type=Path)
    p.add_argument("exe71", type=Path)
    p.add_argument("methods71", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--old-owner", default="KGCKOFPFBLA")
    p.add_argument("--new-owner", default="KLLNGCPBLMM")
    p.add_argument("--old-target-rva", default="0xB6F18D0")
    p.add_argument("--candidate", action="append", default=["36641:0xF045790", "20290:0xF0462A0"])
    p.add_argument("--radius", type=int, default=14)
    args = p.parse_args()

    old_owner, old_all_rvas = _read_old_owner(args.dump70, args.old_owner)
    new_all_rows, new_owner_rows = _read_current_methods(args.methods71, args.new_owner)
    new_all_starts = [rva for rva, _ in new_all_rows]
    old_target = int(args.old_target_rva, 0)

    old_methods = old_owner.get("methods", [])
    old_target_pos = next((i for i, m in enumerate(old_methods) if int(m.get("rva") or 0) == old_target), None)
    if old_target_pos is None:
        raise RuntimeError(f"historical target {old_target:#x} not found in {args.old_owner}")

    candidates = []
    for spec in args.candidate:
        label, rva_text = spec.split(":", 1)
        rva = int(rva_text, 0)
        pos = next((i for i, (mrva, _) in enumerate(new_owner_rows) if mrva == rva), None)
        if pos is None:
            raise RuntimeError(f"candidate {label} {rva:#x} not found in {args.new_owner}")
        candidates.append({"label": label, "rva": rva, "owner_position": pos})

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    old_fp = {}
    new_fp = {}
    with PEImage(args.exe70) as image70:
        for pos in range(max(0, old_target_pos - args.radius), min(len(old_methods), old_target_pos + args.radius + 1)):
            method = old_methods[pos]
            start = int(method.get("rva") or 0)
            if start <= 0:
                continue
            end = _end_for(start, old_all_rvas)
            if end is None:
                continue
            fp = _fingerprint(image70, md, start, end)
            if fp:
                old_fp[pos] = {"method": method, "start": start, "end": end, "fp": fp}

    with PEImage(args.exe71) as image71:
        for pos, (start, row) in enumerate(new_owner_rows):
            end = _end_for(start, new_all_starts)
            if end is None:
                continue
            fp = _fingerprint(image71, md, start, end)
            if fp:
                new_fp[pos] = {"row": row, "start": start, "end": end, "fp": fp}

    old_rows = []
    for old_pos in sorted(old_fp):
        old_item = old_fp[old_pos]
        matches = []
        for new_pos, new_item in new_fp.items():
            sim = _similarity(old_item["fp"], new_item["fp"])
            matches.append({
                **sim,
                "new_owner_position": new_pos,
                "method_index": int(new_item["row"].get("method_index") or 0),
                "method_name": new_item["row"].get("method_name", ""),
                "rva": f"0x{new_item['start']:X}",
                "size": new_item["fp"]["size"],
                "parameter_types": new_item["row"].get("parameter_types", ""),
            })
        matches.sort(key=lambda x: x["score"], reverse=True)
        best = matches[:8]
        old_rows.append({
            "old_owner_position": old_pos,
            "relative_to_rsp": old_pos - old_target_pos,
            "method_index": old_item["method"].get("idx"),
            "method_name": old_item["method"].get("name"),
            "rva": f"0x{old_item['start']:X}",
            "size": old_item["fp"]["size"],
            "parameters": old_item["method"].get("params") or [],
            "return_type": old_item["method"].get("ret", ""),
            "top_current_matches": best,
        })

    # Candidate-local support: for every historical neighbor except the ack itself,
    # reward high-confidence current matches that land close to each candidate while
    # preserving the old neighbor's sign (before/after) relative to the response.
    support = []
    for candidate in candidates:
        cpos = candidate["owner_position"]
        weighted = 0.0
        evidence = []
        for old_row in old_rows:
            rel = old_row["relative_to_rsp"]
            if rel == 0:
                continue
            for match in old_row["top_current_matches"][:4]:
                new_rel = match["new_owner_position"] - cpos
                same_side = (rel < 0 and new_rel < 0) or (rel > 0 and new_rel > 0)
                if not same_side or abs(new_rel) > args.radius * 2:
                    continue
                score = float(match["score"])
                if score < 0.62:
                    continue
                proximity = 1.0 / (1.0 + abs(abs(new_rel) - abs(rel)))
                contribution = (score - 0.60) * proximity
                weighted += contribution
                evidence.append({
                    "old_relative": rel,
                    "old_rva": old_row["rva"],
                    "old_method": old_row["method_name"],
                    "new_relative": new_rel,
                    "new_rva": match["rva"],
                    "new_method": match["method_name"],
                    "similarity": score,
                    "contribution": contribution,
                })
        evidence.sort(key=lambda x: x["contribution"], reverse=True)
        support.append({
            **candidate,
            "weighted_neighborhood_support": weighted,
            "evidence": evidence[:24],
        })

    result = {
        "historical": {
            "owner": args.old_owner,
            "rsp_rva": f"0x{old_target:X}",
            "rsp_owner_position": old_target_pos,
            "window_radius": args.radius,
        },
        "current": {"owner": args.new_owner, "candidate_count": len(candidates)},
        "candidate_support": support,
        "historical_window_matches": old_rows,
        "notes": [
            "Each method is fingerprinted from normalized x64 instruction structure; absolute code/global addresses are erased.",
            "The known ack method itself is intentionally excluded from candidate-local support because both 36641 and 20290 share its generic native body.",
            "Neighborhood support is heuristic until several independent neighboring methods align coherently; raw per-method matches are emitted for review.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("historical rsp position", old_target_pos)
    for row in support:
        print(row["label"], f"0x{row['rva']:X}", "position", row["owner_position"], "support", f"{row['weighted_neighborhood_support']:.6f}")
        for ev in row["evidence"][:8]:
            print(" ", ev)
    print("top global mappings around old rsp:")
    for row in old_rows:
        if row["relative_to_rsp"] == 0:
            continue
        best = row["top_current_matches"][0] if row["top_current_matches"] else None
        if best and best["score"] >= 0.62:
            print(row["relative_to_rsp"], row["rva"], row["method_name"], "=>", best["rva"], best["method_name"], f"{best['score']:.4f}")


if __name__ == "__main__":
    main()
