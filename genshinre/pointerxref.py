from __future__ import annotations

import argparse
import json
from pathlib import Path

from .pe import PEImage
from .xrefs import scan_rip_xrefs, write_json

EXECUTABLE_SECTION = 0x20000000


def scan_pointer_holders(
    data: bytes,
    *,
    section_rva: int,
    image_base: int,
    target_start_rva: int,
    target_end_rva: int,
    alignment: int = 8,
) -> list[dict[str, int]]:
    """Find aligned qword VAs that point into a half-open RVA range."""

    if target_start_rva < 0 or target_end_rva <= target_start_rva:
        raise ValueError("target RVA range must be non-negative and non-empty")
    if alignment <= 0:
        raise ValueError("alignment must be positive")

    first_offset = (-section_rva) % alignment
    rows: list[dict[str, int]] = []
    for offset in range(first_offset, max(first_offset, len(data) - 7), alignment):
        if offset + 8 > len(data):
            break
        value_va = int.from_bytes(data[offset : offset + 8], "little", signed=False)
        if value_va < image_base:
            continue
        target_rva = value_va - image_base
        if not target_start_rva <= target_rva < target_end_rva:
            continue
        rows.append(
            {
                "holder_rva": section_rva + offset,
                "value_va": value_va,
                "target_rva": target_rva,
            }
        )
    return rows


def scan_pointer_xrefs(
    exe: Path,
    target_start_rva: int,
    target_end_rva: int,
    *,
    alignment: int = 8,
    window: int = 48,
    include_executable_holders: bool = False,
) -> dict[str, object]:
    """Find data qwords pointing into an RVA range, then find code xrefs to them."""

    holders: list[dict[str, object]] = []
    scanned_sections: list[str] = []
    with PEImage(exe) as image:
        image_base = image.image_base
        for section in image.sections:
            if not include_executable_holders and section.characteristics & EXECUTABLE_SECTION:
                continue
            if section.raw_size < 8:
                continue
            data = image.read_rva(section.virtual_address, section.raw_size)
            if len(data) != section.raw_size:
                raise ValueError(
                    f"truncated PE section read for {section.name}: "
                    f"expected {section.raw_size} bytes, got {len(data)}"
                )
            scanned_sections.append(section.name)
            for row in scan_pointer_holders(
                data,
                section_rva=section.virtual_address,
                image_base=image_base,
                target_start_rva=target_start_rva,
                target_end_rva=target_end_rva,
                alignment=alignment,
            ):
                holders.append({**row, "section": section.name})

    holder_rvas = sorted({int(row["holder_rva"]) for row in holders})
    code_scan = (
        scan_rip_xrefs(exe, holder_rvas, window=window)
        if holder_rvas
        else {"matches": {}, "scanned_sections": []}
    )

    formatted: list[dict[str, object]] = []
    for row in holders:
        holder_rva = int(row["holder_rva"])
        key = f"0x{holder_rva:X}"
        formatted.append(
            {
                "section": row["section"],
                "holder_rva": key,
                "value_va": f"0x{int(row['value_va']):X}",
                "target_rva": f"0x{int(row['target_rva']):X}",
                "code_xrefs": code_scan["matches"].get(key, []),
            }
        )

    return {
        "target_start_rva": f"0x{target_start_rva:X}",
        "target_end_rva": f"0x{target_end_rva:X}",
        "range_semantics": "half-open",
        "alignment": alignment,
        "include_executable_holders": include_executable_holders,
        "scanned_holder_sections": scanned_sections,
        "holder_count": len(formatted),
        "holders_with_code_xrefs": sum(bool(row["code_xrefs"]) for row in formatted),
        "holders": formatted,
    }


def _rva(text: str) -> int:
    return int(text, 0)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.pointerxref",
        description=(
            "Find file-backed qword pointers into an RVA range and simple "
            "RIP-relative code xrefs to those pointer holders."
        ),
    )
    parser.add_argument("exe", type=Path)
    parser.add_argument("target_start_rva", type=_rva)
    parser.add_argument("target_end_rva", type=_rva)
    parser.add_argument("--alignment", type=int, default=8)
    parser.add_argument("--window", type=int, default=48)
    parser.add_argument("--include-executable-holders", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    result = scan_pointer_xrefs(
        args.exe,
        args.target_start_rva,
        args.target_end_rva,
        alignment=args.alignment,
        window=args.window,
        include_executable_holders=args.include_executable_holders,
    )
    if args.output:
        write_json(result, args.output)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
