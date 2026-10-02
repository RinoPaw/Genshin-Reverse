from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

from genshinre.mhy71 import METHOD_POINTER_TABLE_RVA
from genshinre.pe import PEImage

ROOT_SLOT_RVA = 0x057831E8
SECOND_LEVEL_OFFSET = 0x24F40
COMMON_DISPATCH_RVA = 0x0DD50D00

FOCUS = {
    "unlock_sender": 615754,
    "rsp_36641": 615758,
    "rsp_20290": 615762,
    "get_scene_area_rsp": 615764,
    "scene_point_unlock_notify": 615937,
    "scene_trans_to_point_rsp": 615951,
    "scene_area_unlock_notify": 616105,
}


def u64(data: bytes) -> int:
    return struct.unpack_from("<Q", data)[0]


def ptr_info(image: PEImage, va: int) -> dict[str, object]:
    rva = va - image.image_base if va else 0
    return {
        "va": f"0x{va:X}" if va else "0x0",
        "rva": f"0x{rva:X}" if rva else "0x0",
        "inside_image": 0 < rva < image.size_of_image,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("exe", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    report: dict[str, object] = {
        "root_slot_rva": f"0x{ROOT_SLOT_RVA:X}",
        "second_level_offset": f"0x{SECOND_LEVEL_OFFSET:X}",
        "canonical_method_pointer_table_rva": f"0x{METHOD_POINTER_TABLE_RVA:X}",
        "focus": {},
    }

    with PEImage(args.exe) as image:
        root_va = u64(image.read_rva(ROOT_SLOT_RVA, 8))
        root_rva = root_va - image.image_base if root_va else 0
        report["image_base"] = f"0x{image.image_base:X}"
        report["root_pointer"] = ptr_info(image, root_va)

        second_field_rva = root_rva + SECOND_LEVEL_OFFSET if root_rva else 0
        second_va = u64(image.read_rva(second_field_rva, 8)) if second_field_rva else 0
        second_rva = second_va - image.image_base if second_va else 0
        report["second_level_field_rva"] = f"0x{second_field_rva:X}" if second_field_rva else "0x0"
        report["second_level_pointer"] = ptr_info(image, second_va)
        report["second_level_equals_method_pointer_table"] = second_rva == METHOD_POINTER_TABLE_RVA
        report["second_level_delta_from_method_pointer_table"] = (
            second_rva - METHOD_POINTER_TABLE_RVA if second_va else None
        )

        focus_rows: dict[str, object] = {}
        for label, index in FOCUS.items():
            canonical_va = u64(image.read_rva(METHOD_POINTER_TABLE_RVA + index * 8, 8))
            companion_index = index + 4
            canonical_companion_va = u64(
                image.read_rva(METHOD_POINTER_TABLE_RVA + companion_index * 8, 8)
            )
            via_second_va = 0
            if second_rva > 0:
                via_second_va = u64(image.read_rva(second_rva + companion_index * 8, 8))
            focus_rows[label] = {
                "method_index": index,
                "canonical_method_pointer": ptr_info(image, canonical_va),
                "companion_index": companion_index,
                "companion_offset": f"0x{companion_index * 8:X}",
                "canonical_companion_pointer": ptr_info(image, canonical_companion_va),
                "second_level_companion_pointer": ptr_info(image, via_second_va),
                "companion_values_equal": canonical_companion_va == via_second_va,
            }
        report["focus"] = focus_rows

        # The common tail target receives rcx from the second-level table.
        # Preserve a compact native window so the table's consumer semantics can be audited.
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        blob = image.read_rva(COMMON_DISPATCH_RVA, 0x180)
        rows = []
        for insn in md.disasm(blob, image.image_base + COMMON_DISPATCH_RVA):
            row: dict[str, object] = {
                "rva": f"0x{insn.address - image.image_base:X}",
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": insn.bytes.hex(),
            }
            direct_target = None
            if insn.mnemonic in ("call", "jmp") and insn.operands and insn.operands[0].type == X86_OP_IMM:
                direct_target = int(insn.operands[0].imm) - image.image_base
            if direct_target is not None:
                row["direct_target_rva"] = f"0x{direct_target:X}"
            rip_targets = []
            for op in insn.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    target_va = int(insn.address + insn.size + op.mem.disp)
                    rip_targets.append(f"0x{target_va - image.image_base:X}")
            if rip_targets:
                row["rip_targets"] = rip_targets
            rows.append(row)
        report["common_dispatch"] = {
            "rva": f"0x{COMMON_DISPATCH_RVA:X}",
            "instructions": rows,
        }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "second_level_pointer": report["second_level_pointer"],
        "equals_method_pointer_table": report["second_level_equals_method_pointer_table"],
        "delta": report["second_level_delta_from_method_pointer_table"],
        "focus": {
            k: {
                "companion_index": v["companion_index"],
                "companion_values_equal": v["companion_values_equal"],
                "canonical_companion_rva": v["canonical_companion_pointer"]["rva"],
                "second_level_companion_rva": v["second_level_companion_pointer"]["rva"],
            }
            for k, v in focus_rows.items()
        },
    }, indent=2))


if __name__ == "__main__":
    main()
