from __future__ import annotations

import argparse
import bisect
import csv
import json
import re
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

from genshinre.mhy71 import METHOD_POINTER_TABLE_RVA
from genshinre.pe import PEImage

ROOT_SLOT_RVA = 0x057831E8
SECOND_LEVEL_OFFSET = 0x24F40
COMMON_DISPATCH_RVA = 0x0DD50D00
IMAGE_SCN_MEM_EXECUTE = 0x20000000

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


def load_method_index(path: Path | None) -> tuple[list[int], dict[int, dict[str, object]]]:
    if path is None:
        return [], {}
    by_rva: dict[int, dict[str, object]] = {}
    with path.open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            raw = row.get("rva") or ""
            if not raw:
                continue
            try:
                rva = int(raw, 0)
            except ValueError:
                continue
            if rva <= 0:
                continue
            by_rva.setdefault(
                rva,
                {
                    "rva": f"0x{rva:X}",
                    "method_index": row.get("method_index"),
                    "type_definition_index": row.get("type_definition_index"),
                    "type_name": row.get("type_name"),
                    "method_name": row.get("method_name"),
                },
            )
    return sorted(by_rva), by_rva


def method_owner(rva: int, starts: list[int], by_rva: dict[int, dict[str, object]]) -> dict[str, object] | None:
    if not starts:
        return None
    i = bisect.bisect_right(starts, rva) - 1
    if i < 0:
        return None
    start = starts[i]
    end = starts[i + 1] if i + 1 < len(starts) else start + 0x10000
    if not (start <= rva < end):
        return None
    out = dict(by_rva[start])
    out["offset"] = rva - start
    out["end_rva"] = f"0x{end:X}"
    return out


def scan_root_slot_xrefs(
    image: PEImage,
    method_starts: list[int],
    methods_by_rva: dict[int, dict[str, object]],
) -> list[dict[str, object]]:
    # Match common x64 RIP-relative forms without disassembling the whole executable.
    # Every raw hit is then validated by Capstone from the candidate instruction boundary.
    patterns = [
        re.compile(rb"[\x40-\x4f][\x8b\x89\x8d][\x05\x0d\x15\x1d\x25\x2d\x35\x3d].{4}", re.DOTALL),
        re.compile(rb"[\x8b\x89\x8d][\x05\x0d\x15\x1d\x25\x2d\x35\x3d].{4}", re.DOTALL),
        re.compile(rb"[\x80\x83][\x3d].{5}", re.DOTALL),
        re.compile(rb"\xc6\x05.{5}", re.DOTALL),
        re.compile(rb"\xc7\x05.{8}", re.DOTALL),
    ]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    rows: list[dict[str, object]] = []
    seen: set[int] = set()

    for section in image.sections:
        if not (section.characteristics & IMAGE_SCN_MEM_EXECUTE):
            continue
        size = min(section.raw_size, section.virtual_size or section.raw_size)
        if size <= 0:
            continue
        blob = image.read_rva(section.virtual_address, size)
        for pattern in patterns:
            for match in pattern.finditer(blob):
                rva = section.virtual_address + match.start()
                if rva in seen:
                    continue
                raw = image.read_rva(rva, 16)
                insns = list(md.disasm(raw, image.image_base + rva, count=1))
                if not insns:
                    continue
                insn = insns[0]
                targets: list[int] = []
                for op in insn.operands:
                    if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                        targets.append(int(insn.address + insn.size + op.mem.disp) - image.image_base)
                if ROOT_SLOT_RVA not in targets:
                    continue
                seen.add(rva)
                mnemonic = insn.mnemonic
                # x86 Intel syntax: memory destination on common stores.
                access = "unknown"
                if mnemonic in ("mov", "movq", "movaps", "movups"):
                    if insn.operands and insn.operands[0].type == X86_OP_MEM:
                        access = "write"
                    else:
                        access = "read"
                elif mnemonic == "lea":
                    access = "address"
                elif mnemonic.startswith(("cmp", "test")):
                    access = "read"
                row = {
                    "rva": f"0x{rva:X}",
                    "mnemonic": mnemonic,
                    "op_str": insn.op_str,
                    "bytes": insn.bytes.hex(),
                    "access": access,
                    "owner": method_owner(rva, method_starts, methods_by_rva),
                }
                rows.append(row)
    rows.sort(key=lambda x: int(str(x["rva"]), 0))
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("exe", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--methods", type=Path)
    args = parser.parse_args()

    method_starts, methods_by_rva = load_method_index(args.methods)
    report: dict[str, object] = {
        "root_slot_rva": f"0x{ROOT_SLOT_RVA:X}",
        "second_level_offset": f"0x{SECOND_LEVEL_OFFSET:X}",
        "canonical_method_pointer_table_rva": f"0x{METHOD_POINTER_TABLE_RVA:X}",
        "focus": {},
    }

    with PEImage(args.exe) as image:
        raw_root = image.read_rva(ROOT_SLOT_RVA, 8)
        if len(raw_root) != 8:
            raise ValueError("cannot read scene-handler root slot")
        root_va = u64(raw_root)
        root = ptr_info(image, root_va)
        report["image_base"] = f"0x{image.image_base:X}"
        report["root_slot_raw_bytes"] = raw_root.hex()
        report["root_slot_raw_u64"] = f"0x{root_va:X}"
        report["root_pointer_if_plain"] = root
        report["root_slot_plain_pointer_valid"] = bool(root["inside_image"])
        report["root_slot_xrefs"] = scan_root_slot_xrefs(image, method_starts, methods_by_rva)
        report["root_slot_xref_summary"] = {
            "total": len(report["root_slot_xrefs"]),
            "reads": sum(x["access"] == "read" for x in report["root_slot_xrefs"]),
            "writes": sum(x["access"] == "write" for x in report["root_slot_xrefs"]),
            "addresses": sum(x["access"] == "address" for x in report["root_slot_xrefs"]),
        }

        # Dereference only when the on-disk value is an actual in-image pointer.
        if root["inside_image"]:
            root_rva = root_va - image.image_base
            second_field_rva = root_rva + SECOND_LEVEL_OFFSET
            second_raw = image.read_rva(second_field_rva, 8)
            second_va = u64(second_raw) if len(second_raw) == 8 else 0
            report["second_level_field_rva"] = f"0x{second_field_rva:X}"
            report["second_level_pointer_if_plain"] = ptr_info(image, second_va)
        else:
            report["second_level_field_rva"] = None
            report["second_level_pointer_if_plain"] = None

        focus_rows: dict[str, object] = {}
        for label, index in FOCUS.items():
            canonical_raw = image.read_rva(METHOD_POINTER_TABLE_RVA + index * 8, 8)
            canonical_va = u64(canonical_raw) if len(canonical_raw) == 8 else 0
            focus_rows[label] = {
                "method_index": index,
                "canonical_method_pointer": ptr_info(image, canonical_va),
            }
        report["focus"] = focus_rows

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
            if insn.mnemonic in ("call", "jmp") and insn.operands and insn.operands[0].type == X86_OP_IMM:
                row["direct_target_rva"] = f"0x{int(insn.operands[0].imm) - image.image_base:X}"
            rip_targets = []
            for op in insn.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    target_va = int(insn.address + insn.size + op.mem.disp)
                    rip_targets.append(f"0x{target_va - image.image_base:X}")
            if rip_targets:
                row["rip_targets"] = rip_targets
            rows.append(row)
        report["common_dispatch"] = {"rva": f"0x{COMMON_DISPATCH_RVA:X}", "instructions": rows}

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "root_slot_raw_u64": report["root_slot_raw_u64"],
        "plain_pointer_valid": report["root_slot_plain_pointer_valid"],
        "root_slot_xref_summary": report["root_slot_xref_summary"],
        "root_slot_xrefs": report["root_slot_xrefs"],
    }, indent=2))


if __name__ == "__main__":
    main()
