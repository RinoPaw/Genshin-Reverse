from __future__ import annotations

import argparse
import bisect
import csv
import json
from collections import Counter
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM

from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_profile_exe


MAGIC_VALUES = {
    0x4567: "head_magic_be",
    0x6745: "head_magic_byteswapped",
    0x89AB: "tail_magic_be",
    0xAB89: "tail_magic_byteswapped",
}

# x86 immediates are little-endian in the instruction stream. Include both
# numeric interpretations because some code compares a host-order uint16 while
# other code can compare the network-order bytes after a swap.
RAW_PATTERNS = {
    bytes.fromhex("6745"): "imm_0x4567",
    bytes.fromhex("4567"): "imm_0x6745",
    bytes.fromhex("ab89"): "imm_0x89ab",
    bytes.fromhex("89ab"): "imm_0xab89",
}


def load_methods(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        for line_no, row in enumerate(csv.DictReader(f), start=2):
            raw = (row.get("rva") or "").strip()
            if not raw:
                continue
            try:
                rva = int(raw, 0)
            except ValueError as exc:
                raise ValueError(f"{path}:{line_no}: invalid method RVA {raw!r}") from exc
            if rva <= 0:
                continue
            rows.append(
                {
                    "rva": rva,
                    "method_index": row.get("method_index", ""),
                    "type_name": row.get("type_name", ""),
                    "method_name": row.get("method_name", ""),
                    "parameter_types": row.get("parameter_types", ""),
                    "return_type": row.get("return_type", ""),
                }
            )
    rows.sort(key=lambda x: int(x["rva"]))
    return rows


def method_end(starts: list[int], start: int, max_size: int) -> int | None:
    i = bisect.bisect_right(starts, start)
    if i >= len(starts):
        return None
    end = starts[i]
    if end <= start or end - start > max_size:
        return None
    return end


def raw_pattern_counts(blob: bytes) -> dict[str, int]:
    return {name: blob.count(pattern) for pattern, name in RAW_PATTERNS.items() if pattern in blob}


def classify_immediate(value: int) -> str | None:
    return MAGIC_VALUES.get(value & 0xFFFF) if 0 <= value <= 0xFFFF else None


def main() -> None:
    p = argparse.ArgumentParser(
        description=(
            "Locate current-7.1 native methods that reference the decrypted game-packet "
            "framing magics 0x4567 and 0x89AB."
        )
    )
    p.add_argument("exe", type=Path)
    p.add_argument("methods_csv", type=Path)
    p.add_argument("output_json", type=Path)
    p.add_argument("--max-method-size", type=lambda x: int(x, 0), default=0x5000)
    args = p.parse_args()

    exe_sha256 = require_profile_exe(args.exe, PROFILE_71)
    methods = load_methods(args.methods_csv)
    starts = [int(row["rva"]) for row in methods]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    candidates = []
    raw_hit_methods = 0
    direct_immediate_counts: Counter[int] = Counter()

    with PEImage(args.exe) as image:
        for row in methods:
            start = int(row["rva"])
            end = method_end(starts, start, args.max_method_size)
            if end is None:
                continue
            blob = image.read_rva(start, end - start)
            if len(blob) != end - start:
                raise ValueError(
                    f"method body read truncated at 0x{start:X}: expected {end-start}, got {len(blob)}"
                )

            raw_counts = raw_pattern_counts(blob)
            if not raw_counts:
                continue
            raw_hit_methods += 1

            insns = list(md.disasm(blob, image.image_base + start))
            immediate_hits = []
            for index, insn in enumerate(insns):
                for operand in insn.operands:
                    if operand.type != X86_OP_IMM:
                        continue
                    value = int(operand.imm)
                    label = classify_immediate(value)
                    if label is None:
                        continue
                    direct_immediate_counts[value & 0xFFFF] += 1
                    lo = max(0, index - 8)
                    hi = min(len(insns), index + 9)
                    immediate_hits.append(
                        {
                            "rva": f"0x{insn.address - image.image_base:X}",
                            "mnemonic": insn.mnemonic,
                            "op_str": insn.op_str,
                            "value": f"0x{value & 0xFFFF:04X}",
                            "label": label,
                            "context": [
                                {
                                    "rva": f"0x{x.address - image.image_base:X}",
                                    "mnemonic": x.mnemonic,
                                    "op_str": x.op_str,
                                }
                                for x in insns[lo:hi]
                            ],
                        }
                    )

            if not immediate_hits:
                continue

            labels = {hit["label"] for hit in immediate_hits}
            has_head = any(label.startswith("head_magic") for label in labels)
            has_tail = any(label.startswith("tail_magic") for label in labels)
            candidates.append(
                {
                    **row,
                    "rva": f"0x{start:X}",
                    "end_rva": f"0x{end:X}",
                    "size": end - start,
                    "raw_pattern_counts": raw_counts,
                    "has_head_magic_immediate": has_head,
                    "has_tail_magic_immediate": has_tail,
                    "both_magics": has_head and has_tail,
                    "immediate_hits": immediate_hits,
                }
            )

    candidates.sort(
        key=lambda x: (
            not bool(x["both_magics"]),
            -(len(x["immediate_hits"])),
            int(str(x["rva"]), 0),
        )
    )

    result = {
        "profile": PROFILE_71.identity,
        "exe": str(args.exe),
        "exe_sha256": exe_sha256,
        "methods_csv": str(args.methods_csv),
        "method_count": len(methods),
        "raw_hit_method_count": raw_hit_methods,
        "validated_immediate_method_count": len(candidates),
        "direct_immediate_counts": {f"0x{k:04X}": v for k, v in sorted(direct_immediate_counts.items())},
        "candidates": candidates,
        "notes": [
            "Raw byte patterns are only a prefilter; candidates are emitted only when Capstone decodes a matching immediate operand.",
            "A method containing both framing magics is a stronger packet-framing lead than a method containing only one.",
            "No candidate is a hook identity until its caller/callee context and decrypted-buffer lifetime are inspected.",
        ],
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("methods", len(methods))
    print("raw-hit methods", raw_hit_methods)
    print("validated immediate methods", len(candidates))
    print("direct immediate counts", dict(direct_immediate_counts))
    for row in candidates[:40]:
        print(
            row["rva"],
            row["type_name"],
            row["method_name"],
            "both=" + str(row["both_magics"]),
            "hits=" + ",".join(hit["value"] for hit in row["immediate_hits"]),
        )


if __name__ == "__main__":
    main()
