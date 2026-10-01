from __future__ import annotations

import argparse
import json
from pathlib import Path

from .pe import PEImage
from .usage import INITIALIZER_RVA_71


def diagnose_initializer_flow_71(
    exe: Path,
    output_json: Path,
    size: int = 0x800,
) -> dict[str, object]:
    try:
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs
        from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
    except ImportError as exc:
        raise RuntimeError("initializerflowdiag requires capstone") from exc

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    with PEImage(exe) as image:
        blob = image.read_rva(INITIALIZER_RVA_71, size)
        insns = list(md.disasm(blob, INITIALIZER_RVA_71)) if blob else []

    rows: list[dict[str, object]] = []
    rip_targets: dict[str, list[str]] = {}
    direct_calls: list[dict[str, object]] = []
    indexed_memory: list[dict[str, object]] = []

    for insn in insns:
        operands: list[dict[str, object]] = []
        row_rip_targets: list[str] = []
        has_indexed_mem = False
        for op in insn.operands:
            if op.type == X86_OP_REG:
                operands.append({"type": "reg", "reg": insn.reg_name(op.reg)})
            elif op.type == X86_OP_IMM:
                operands.append({"type": "imm", "value": int(op.imm), "hex": f"0x{int(op.imm) & 0xFFFFFFFFFFFFFFFF:X}"})
            elif op.type == X86_OP_MEM:
                mem = {
                    "type": "mem",
                    "base": insn.reg_name(op.mem.base) if op.mem.base else "",
                    "index": insn.reg_name(op.mem.index) if op.mem.index else "",
                    "scale": op.mem.scale,
                    "disp": op.mem.disp,
                }
                if op.mem.base == X86_REG_RIP:
                    target = insn.address + insn.size + op.mem.disp
                    mem["rip_target"] = f"0x{target:X}"
                    row_rip_targets.append(f"0x{target:X}")
                if op.mem.index or (op.mem.base and op.mem.base != X86_REG_RIP):
                    has_indexed_mem = True
                operands.append(mem)
        row = {
            "rva": f"0x{insn.address:X}",
            "bytes": insn.bytes.hex(" "),
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
            "operands": operands,
        }
        rows.append(row)
        for target in row_rip_targets:
            rip_targets.setdefault(target, []).append(f"0x{insn.address:X}")
        if has_indexed_mem:
            indexed_memory.append(row)
        if insn.mnemonic == "call" and insn.operands and insn.operands[0].type == X86_OP_IMM:
            direct_calls.append({"rva": f"0x{insn.address:X}", "target": f"0x{int(insn.operands[0].imm):X}", "op_str": insn.op_str})

    result: dict[str, object] = {
        "initializer_rva": f"0x{INITIALIZER_RVA_71:X}",
        "requested_size": size,
        "instruction_count": len(insns),
        "rip_targets": rip_targets,
        "direct_calls": direct_calls,
        "indexed_memory": indexed_memory,
        "instructions": rows,
    }
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m genshinre.initializerflowdiag")
    parser.add_argument("exe", type=Path)
    parser.add_argument("output_json", type=Path)
    parser.add_argument("--size", type=lambda value: int(value, 0), default=0x800)
    args = parser.parse_args()
    result = diagnose_initializer_flow_71(args.exe, args.output_json, size=args.size)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
