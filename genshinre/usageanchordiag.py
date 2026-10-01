from __future__ import annotations

import argparse
import bisect
import csv
import json
from pathlib import Path

from .pe import PEImage
from .usage import INITIALIZER_RVA_71


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def _int(value: object) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _method_rvas(text: str) -> list[int]:
    result: list[int] = []
    for part in text.split("|"):
        part = part.strip()
        if "@0x" not in part:
            continue
        try:
            result.append(int(part.rsplit("@0x", 1)[1], 16))
        except ValueError:
            pass
    return sorted(set(result))


def diagnose_anchor(
    exe: Path,
    methods_csv: Path,
    type_cache_xrefs_csv: Path,
    output_json: Path,
    cmd_id: int,
    context_before: int = 28,
    context_after: int = 12,
    max_method_bytes: int = 0x5000,
) -> dict[str, object]:
    try:
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs
        from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
    except ImportError as exc:
        raise RuntimeError("usageanchordiag requires capstone") from exc

    methods = _rows(methods_csv)
    xrefs = _rows(type_cache_xrefs_csv)
    primary = [
        row for row in xrefs
        if _int(row.get("cmd_id")) == cmd_id
        and row.get("status") in {"UNIQUE_SLOT_XREF", "DOMINANT_SLOT_XREF"}
    ]
    if len(primary) != 1:
        raise ValueError(f"CmdId {cmd_id} has {len(primary)} primary type-cache xref rows")
    identity = primary[0]
    slot = _int(identity.get("registry_slot_rva"))
    tdi = _int(identity.get("type_definition_index"))
    if slot is None or tdi is None:
        raise ValueError("anchor identity lacks slot or TDI")

    by_rva: dict[int, dict[str, str]] = {}
    all_rvas: set[int] = set()
    for row in methods:
        rva = _int(row.get("rva"))
        if rva is None:
            continue
        all_rvas.add(rva)
        by_rva.setdefault(rva, row)
    sorted_rvas = sorted(all_rvas)

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    method_results: list[dict[str, object]] = []
    target_method_rvas = _method_rvas(str(identity.get("xref_methods", "")))

    with PEImage(exe) as image:
        for method_rva in target_method_rvas:
            pos = bisect.bisect_right(sorted_rvas, method_rva)
            next_rva = sorted_rvas[pos] if pos < len(sorted_rvas) else method_rva + max_method_bytes
            size = min(max(next_rva - method_rva, 1), max_method_bytes)
            blob = image.read_rva(method_rva, size)
            insns = list(md.disasm(blob, method_rva)) if blob else []
            calls: list[dict[str, object]] = []
            slot_refs: list[dict[str, object]] = []

            for idx, insn in enumerate(insns):
                slot_hit = False
                for operand in insn.operands:
                    if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                        target = insn.address + insn.size + operand.mem.disp
                        if target == slot:
                            slot_hit = True
                            slot_refs.append(
                                {
                                    "index": idx,
                                    "rva": f"0x{insn.address:X}",
                                    "text": f"{insn.mnemonic} {insn.op_str}",
                                }
                            )

                is_initializer = (
                    insn.mnemonic == "call"
                    and bool(insn.operands)
                    and insn.operands[0].type == X86_OP_IMM
                    and int(insn.operands[0].imm) == INITIALIZER_RVA_71
                )
                if not is_initializer:
                    continue

                start = max(0, idx - context_before)
                end = min(len(insns), idx + context_after + 1)
                context: list[dict[str, object]] = []
                immediate_arg_writes: list[dict[str, object]] = []
                for cidx in range(start, end):
                    cur = insns[cidx]
                    item: dict[str, object] = {
                        "relative_instruction": cidx - idx,
                        "rva": f"0x{cur.address:X}",
                        "bytes": cur.bytes.hex(" "),
                        "mnemonic": cur.mnemonic,
                        "op_str": cur.op_str,
                    }
                    rip_targets: list[str] = []
                    for op in cur.operands:
                        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                            rip_targets.append(f"0x{cur.address + cur.size + op.mem.disp:X}")
                    if rip_targets:
                        item["rip_targets"] = rip_targets
                    context.append(item)

                    if len(cur.operands) == 2 and cur.operands[0].type == X86_OP_REG and cur.operands[1].type == X86_OP_IMM:
                        reg = cur.reg_name(cur.operands[0].reg)
                        if reg in {"ecx", "rcx", "edx", "rdx", "r8d", "r8", "r9d", "r9", "eax", "rax"}:
                            immediate_arg_writes.append(
                                {
                                    "relative_instruction": cidx - idx,
                                    "rva": f"0x{cur.address:X}",
                                    "register": reg,
                                    "immediate": int(cur.operands[1].imm) & 0xFFFFFFFFFFFFFFFF,
                                    "immediate_hex": f"0x{int(cur.operands[1].imm) & 0xFFFFFFFFFFFFFFFF:X}",
                                    "text": f"{cur.mnemonic} {cur.op_str}",
                                }
                            )

                nearest_slot_ref = None
                if slot_refs:
                    nearest_slot_ref = min(slot_refs, key=lambda item: abs(int(str(item["rva"]), 0) - insn.address))
                calls.append(
                    {
                        "call_index": idx,
                        "call_rva": f"0x{insn.address:X}",
                        "nearest_slot_ref": nearest_slot_ref,
                        "immediate_arg_writes": immediate_arg_writes,
                        "context": context,
                    }
                )

            method = by_rva.get(method_rva, {})
            method_results.append(
                {
                    "method_rva": f"0x{method_rva:X}",
                    "method_name": str(method.get("method_name", "")),
                    "declaring_type_definition_index": _int(method.get("type_definition_index")),
                    "instruction_count": len(insns),
                    "slot_refs": slot_refs,
                    "initializer_calls": calls,
                }
            )

    result: dict[str, object] = {
        "cmd_id": cmd_id,
        "type_name": identity.get("type_name"),
        "type_definition_index": tdi,
        "registry_slot_rva": f"0x{slot:X}",
        "get_cmd_id_rva": identity.get("get_cmd_id_rva"),
        "xref_methods_source": identity.get("xref_methods"),
        "initializer_rva": f"0x{INITIALIZER_RVA_71:X}",
        "methods": method_results,
    }
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m genshinre.usageanchordiag")
    parser.add_argument("exe", type=Path)
    parser.add_argument("methods_csv", type=Path)
    parser.add_argument("type_cache_xrefs_csv", type=Path)
    parser.add_argument("output_json", type=Path)
    parser.add_argument("--cmd-id", type=lambda value: int(value, 0), default=9369)
    parser.add_argument("--context-before", type=int, default=28)
    parser.add_argument("--context-after", type=int, default=12)
    args = parser.parse_args()
    result = diagnose_anchor(
        args.exe,
        args.methods_csv,
        args.type_cache_xrefs_csv,
        args.output_json,
        args.cmd_id,
        context_before=args.context_before,
        context_after=args.context_after,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
