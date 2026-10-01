from __future__ import annotations

import json
import re
from pathlib import Path

from .pe import PEImage

_RIP_PATTERN = re.compile(
    rb"[\x40-\x4F]?[\x8B\x89\x8D][\x05\x0D\x15\x1D\x25\x2D\x35\x3D].{4}",
    re.DOTALL,
)

_OPCODES = {
    0x8B: ("mov", "read"),
    0x89: ("mov", "write"),
    0x8D: ("lea", "address"),
}


def decode_simple_rip_relative(code: bytes, offset: int, instruction_rva: int) -> dict[str, object] | None:
    """Decode a narrow x86-64 RIP-relative MOV/LEA form.

    Supported forms use optional REX, one-byte opcode 8B/89/8D, ModRM mod=00
    r/m=101, then a signed disp32. This intentionally avoids pretending to be a
    general disassembler.
    """

    start = offset
    if start >= len(code):
        return None
    cursor = start
    rex = None
    if 0x40 <= code[cursor] <= 0x4F:
        rex = code[cursor]
        cursor += 1
        if cursor >= len(code):
            return None

    opcode = code[cursor]
    if opcode not in _OPCODES:
        return None
    cursor += 1
    if cursor >= len(code):
        return None

    modrm = code[cursor]
    if (modrm & 0xC7) != 0x05:
        return None
    cursor += 1
    if cursor + 4 > len(code):
        return None

    displacement = int.from_bytes(code[cursor : cursor + 4], "little", signed=True)
    cursor += 4
    length = cursor - start
    target_rva = instruction_rva + length + displacement
    mnemonic, access = _OPCODES[opcode]
    return {
        "instruction_rva": instruction_rva,
        "target_rva": target_rva,
        "length": length,
        "rex": None if rex is None else f"0x{rex:02X}",
        "opcode": f"0x{opcode:02X}",
        "modrm": f"0x{modrm:02X}",
        "mnemonic": mnemonic,
        "access": access,
        "displacement": displacement,
        "instruction_hex": code[start:cursor].hex(),
    }


def scan_rip_xrefs(
    exe: Path,
    target_rvas: list[int],
    window: int = 24,
    executable_sections_only: bool = True,
) -> dict[str, object]:
    targets = set(target_rvas)
    matches: dict[int, list[dict[str, object]]] = {target: [] for target in target_rvas}

    with PEImage(exe) as image:
        scanned_sections: list[str] = []
        for section in image.sections:
            if executable_sections_only and not (section.characteristics & 0x20000000):
                continue
            blob = image.read_rva(section.virtual_address, section.raw_size)
            if not blob:
                continue
            scanned_sections.append(section.name)
            for match in _RIP_PATTERN.finditer(blob):
                instruction_rva = section.virtual_address + match.start()
                decoded = decode_simple_rip_relative(blob, match.start(), instruction_rva)
                if decoded is None:
                    continue
                target = int(decoded["target_rva"])
                if target not in targets:
                    continue
                before = min(window, instruction_rva - section.virtual_address)
                start_rva = instruction_rva - before
                window_bytes = image.read_rva(start_rva, before + int(decoded["length"]) + window)
                decoded.update(
                    {
                        "section": section.name,
                        "window_rva": f"0x{start_rva:X}",
                        "window_hex": window_bytes.hex(),
                    }
                )
                matches[target].append(decoded)

    return {
        "targets": [f"0x{target:X}" for target in target_rvas],
        "executable_sections_only": executable_sections_only,
        "scanned_sections": scanned_sections,
        "matches": {
            f"0x{target:X}": [
                {
                    **row,
                    "instruction_rva": f"0x{int(row['instruction_rva']):X}",
                    "target_rva": f"0x{int(row['target_rva']):X}",
                }
                for row in rows
            ]
            for target, rows in matches.items()
        },
    }


def inspect_rva(exe: Path, rva: int, before: int = 32, after: int = 64) -> dict[str, object]:
    with PEImage(exe) as image:
        section = next(
            (
                item
                for item in image.sections
                if item.virtual_address <= rva < item.virtual_address + max(item.virtual_size, item.raw_size)
            ),
            None,
        )
        if section is None:
            raise ValueError(f"RVA 0x{rva:X} is not mapped by a PE section")
        actual_before = min(before, rva - section.virtual_address)
        start = rva - actual_before
        data = image.read_rva(start, actual_before + after)
        decoded: list[dict[str, object]] = []
        for match in _RIP_PATTERN.finditer(data):
            instruction_rva = start + match.start()
            item = decode_simple_rip_relative(data, match.start(), instruction_rva)
            if item is not None:
                item["instruction_rva"] = f"0x{instruction_rva:X}"
                item["target_rva"] = f"0x{int(item['target_rva']):X}"
                decoded.append(item)
        return {
            "requested_rva": f"0x{rva:X}",
            "section": section.name,
            "window_rva": f"0x{start:X}",
            "focus_offset": actual_before,
            "bytes_hex": data.hex(),
            "simple_rip_relative_instructions": decoded,
        }


def probe_registry_71(exe: Path) -> dict[str, object]:
    anchors = [
        {
            "name": "UnlockTransPointReq type slot",
            "cmd_id": 9369,
            "target_rva": 0x057E6498,
            "expected_store_rva": 0x07F852AB,
        },
        {
            "name": "DoSetPlayerBornDataNotify type slot",
            "cmd_id": 22899,
            "target_rva": 0x057F6F60,
            "expected_store_rva": None,
        },
        {
            "name": "Traveler selection page type slot control",
            "cmd_id": None,
            "target_rva": 0x057DE810,
            "expected_store_rva": None,
        },
    ]
    scan = scan_rip_xrefs(exe, [int(anchor["target_rva"]) for anchor in anchors], window=32)
    results = []
    for anchor in anchors:
        key = f"0x{int(anchor['target_rva']):X}"
        rows = scan["matches"].get(key, [])
        expected = anchor["expected_store_rva"]
        expected_match = None
        if expected is not None:
            expected_match = any(int(str(row["instruction_rva"]), 0) == expected for row in rows)
        results.append(
            {
                **anchor,
                "target_rva": key,
                "expected_store_rva": None if expected is None else f"0x{expected:X}",
                "xref_count": len(rows),
                "expected_store_found": expected_match,
                "xrefs": rows,
            }
        )
    return {
        "scope": "simple RIP-relative MOV/LEA xrefs; discovery/probe output",
        "anchors": results,
        "scanned_sections": scan["scanned_sections"],
    }


def write_json(data: dict[str, object], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
