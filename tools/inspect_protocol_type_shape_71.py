from __future__ import annotations

import argparse
import bisect
import csv
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM

from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_profile_exe


def parse_int(value: str | None) -> int | None:
    text = (value or "").strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def main() -> None:
    p = argparse.ArgumentParser(description="Inspect current 7.1 protocol type methods for protobuf wire-tag comparisons.")
    p.add_argument("exe", type=Path)
    p.add_argument("registry_csv", type=Path)
    p.add_argument("methods_csv", type=Path)
    p.add_argument("output_json", type=Path)
    p.add_argument("--cmd", action="append", required=True)
    p.add_argument("--max-body", type=lambda s: int(s, 0), default=0x1800)
    args = p.parse_args()

    exe_sha256 = require_profile_exe(args.exe, PROFILE_71)
    registry = {int(row["cmd_id"], 0): row for row in load_rows(args.registry_csv)}
    cmd_ids = [int(value, 0) for value in args.cmd]
    missing = [cmd for cmd in cmd_ids if cmd not in registry]
    if missing:
        raise SystemExit(f"CmdIds missing from registry: {missing}")

    methods = []
    by_type: dict[str, list[tuple[int, dict[str, str]]]] = {}
    for line_no, row in enumerate(load_rows(args.methods_csv), start=2):
        text = (row.get("rva") or "").strip()
        if not text:
            continue
        try:
            rva = int(text, 0)
        except ValueError as exc:
            raise ValueError(f"{args.methods_csv}:{line_no}: invalid method RVA {text!r}") from exc
        if rva <= 0:
            continue
        methods.append((rva, row))
        by_type.setdefault(row.get("type_name", ""), []).append((rva, row))
    methods.sort(key=lambda item: item[0])
    starts = [rva for rva, _ in methods]

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    def end_for(rva: int) -> int:
        pos = bisect.bisect_right(starts, rva)
        if pos >= len(starts):
            return rva + args.max_body
        return min(starts[pos], rva + args.max_body)

    report_rows = []
    with PEImage(args.exe) as image:
        for cmd in cmd_ids:
            reg = registry[cmd]
            type_name = reg.get("type_name", "")
            type_methods = sorted(by_type.get(type_name, []))
            scans = []
            for rva, row in type_methods:
                end = end_for(rva)
                if end <= rva:
                    raise ValueError(f"invalid method span at 0x{rva:X}")
                blob = image.read_rva(rva, end - rva)
                if len(blob) != end - rva:
                    raise ValueError(
                        f"method body read truncated at 0x{rva:X}: expected {end-rva}, got {len(blob)}"
                    )
                comparisons = []
                all_insns = []
                small_immediates: set[int] = set()
                for insn in md.disasm(blob, image.image_base + rva):
                    irva = insn.address - image.image_base
                    imms = [int(op.imm) for op in insn.operands if op.type == X86_OP_IMM]
                    for imm in imms:
                        if 0 <= imm <= 0x20000:
                            small_immediates.add(imm)
                    if insn.mnemonic in {"cmp", "test"} and imms:
                        comparisons.append(
                            {
                                "rva": f"0x{irva:X}",
                                "mnemonic": insn.mnemonic,
                                "op_str": insn.op_str,
                                "immediates": imms,
                            }
                        )
                    if len(all_insns) < 320:
                        all_insns.append(f"0x{irva:X}: {insn.mnemonic} {insn.op_str}")
                plausible_tags = sorted(
                    value
                    for value in small_immediates
                    if value > 0 and (value & 7) in {0, 1, 2, 5}
                )
                scans.append(
                    {
                        "method_name": row.get("method_name", ""),
                        "rva": f"0x{rva:X}",
                        "method_index": row.get("method_index", ""),
                        "size": end - rva,
                        "comparison_count": len(comparisons),
                        "comparisons": comparisons,
                        "plausible_wire_tags": plausible_tags,
                        "disasm": all_insns,
                    }
                )
            report_rows.append(
                {
                    "cmd_id": cmd,
                    "semantic_name": reg.get("semantic_name", ""),
                    "type_name": type_name,
                    "type_definition_index": reg.get("type_definition_index", ""),
                    "field_start": reg.get("field_start", ""),
                    "field_count": reg.get("field_count", ""),
                    "get_cmd_id_rva": reg.get("get_cmd_id_rva", ""),
                    "methods": scans,
                }
            )

    report = {
        "profile": PROFILE_71.identity,
        "exe_sha256": exe_sha256,
        "rows": report_rows,
        "notes": [
            "wire-tag candidates come from immediate operands in exact-client methods; parser identity still requires control comparison",
            "field number = tag >> 3 and wire type = tag & 7 for true protobuf tags",
            "small-immediate lists intentionally over-approximate and must be read with surrounding cmp branches",
        ],
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    for item in report_rows:
        print("===", item["cmd_id"], item["type_name"], "fields", item["field_count"], "===")
        for scan in item["methods"]:
            if scan["comparison_count"] or scan["plausible_wire_tags"]:
                print(
                    scan["rva"], scan["method_name"], "cmp", scan["comparison_count"],
                    "tags", scan["plausible_wire_tags"],
                )
                for comp in scan["comparisons"][:80]:
                    print(" ", comp["rva"], comp["mnemonic"], comp["op_str"])


if __name__ == "__main__":
    main()
