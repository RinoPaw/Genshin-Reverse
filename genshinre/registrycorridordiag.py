from __future__ import annotations

import argparse
import json
from pathlib import Path

from .pe import PEImage
from .usage import INITIALIZER_RVA_71


def diagnose_registry_corridor(
    exe: Path,
    output_json: Path,
    center_rva: int = 0x07F852AB,
    before: int = 0x300,
    after: int = 0x180,
    slot_rva: int = 0x057E6498,
    expected_usage: int = 37523,
) -> dict[str, object]:
    try:
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs
        from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
    except ImportError as exc:
        raise RuntimeError("registrycorridordiag requires capstone") from exc

    start = center_rva - before
    size = before + after
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    with PEImage(exe) as image:
        blob = image.read_rva(start, size)
        insns = list(md.disasm(blob, start)) if blob else []

    interesting: list[dict[str, object]] = []
    initializer_calls: list[dict[str, object]] = []
    expected_usage_immediates: list[dict[str, object]] = []
    slot_refs: list[dict[str, object]] = []

    for idx, insn in enumerate(insns):
        rip_targets: list[int] = []
        immediates: list[int] = []
        registers: list[str] = []
        for operand in insn.operands:
            if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                rip_targets.append(insn.address + insn.size + operand.mem.disp)
            elif operand.type == X86_OP_IMM:
                immediates.append(int(operand.imm) & 0xFFFFFFFFFFFFFFFF)
            elif operand.type == X86_OP_REG:
                registers.append(insn.reg_name(operand.reg))

        is_initializer = (
            insn.mnemonic == "call"
            and bool(insn.operands)
            and insn.operands[0].type == X86_OP_IMM
            and int(insn.operands[0].imm) == INITIALIZER_RVA_71
        )
        is_expected_usage = expected_usage in immediates
        is_slot_ref = slot_rva in rip_targets
        is_center = abs(insn.address - center_rva) <= 16
        is_arg_write = (
            len(insn.operands) == 2
            and insn.operands[0].type == X86_OP_REG
            and insn.reg_name(insn.operands[0].reg) in {"ecx", "rcx", "edx", "rdx", "r8d", "r8", "r9d", "r9"}
        )

        if is_initializer or is_expected_usage or is_slot_ref or is_center or is_arg_write:
            row = {
                "index": idx,
                "rva": f"0x{insn.address:X}",
                "bytes": insn.bytes.hex(" "),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "rip_targets": [f"0x{x:X}" for x in rip_targets],
                "immediates": [f"0x{x:X}" for x in immediates],
                "registers": registers,
            }
            interesting.append(row)
            if is_initializer:
                context = []
                for cur in insns[max(0, idx - 20) : min(len(insns), idx + 13)]:
                    context.append(
                        {
                            "relative_instruction": insns.index(cur) - idx,
                            "rva": f"0x{cur.address:X}",
                            "bytes": cur.bytes.hex(" "),
                            "mnemonic": cur.mnemonic,
                            "op_str": cur.op_str,
                        }
                    )
                initializer_calls.append({"call_rva": f"0x{insn.address:X}", "context": context})
            if is_expected_usage:
                expected_usage_immediates.append(row)
            if is_slot_ref:
                slot_refs.append(row)

    result: dict[str, object] = {
        "center_rva": f"0x{center_rva:X}",
        "range": [f"0x{start:X}", f"0x{start + size:X}"],
        "initializer_rva": f"0x{INITIALIZER_RVA_71:X}",
        "expected_usage": expected_usage,
        "expected_usage_hex": f"0x{expected_usage:X}",
        "slot_rva": f"0x{slot_rva:X}",
        "instruction_count": len(insns),
        "initializer_call_count": len(initializer_calls),
        "expected_usage_immediate_count": len(expected_usage_immediates),
        "slot_ref_count": len(slot_refs),
        "initializer_calls": initializer_calls,
        "expected_usage_immediates": expected_usage_immediates,
        "slot_refs": slot_refs,
        "interesting": interesting,
    }
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m genshinre.registrycorridordiag")
    parser.add_argument("exe", type=Path)
    parser.add_argument("output_json", type=Path)
    parser.add_argument("--center-rva", type=lambda x: int(x, 0), default=0x07F852AB)
    parser.add_argument("--before", type=lambda x: int(x, 0), default=0x300)
    parser.add_argument("--after", type=lambda x: int(x, 0), default=0x180)
    parser.add_argument("--slot-rva", type=lambda x: int(x, 0), default=0x057E6498)
    parser.add_argument("--expected-usage", type=lambda x: int(x, 0), default=37523)
    args = parser.parse_args()
    result = diagnose_registry_corridor(
        args.exe,
        args.output_json,
        center_rva=args.center_rva,
        before=args.before,
        after=args.after,
        slot_rva=args.slot_rva,
        expected_usage=args.expected_usage,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
