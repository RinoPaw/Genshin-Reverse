from __future__ import annotations

import csv
from bisect import bisect_right
from pathlib import Path

from .pe import PEImage


def decode_direct_call(code: bytes, offset: int, instruction_rva: int) -> dict[str, object] | None:
    """Decode x86-64 E8 rel32 direct CALL.

    This intentionally recognizes only the five-byte near relative call form.
    Indirect calls are outside this evidence layer.
    """

    if offset < 0 or offset + 5 > len(code) or code[offset] != 0xE8:
        return None
    displacement = int.from_bytes(code[offset + 1 : offset + 5], "little", signed=True)
    target_rva = instruction_rva + 5 + displacement
    return {
        "instruction_rva": instruction_rva,
        "target_rva": target_rva,
        "length": 5,
        "displacement": displacement,
        "instruction_hex": code[offset : offset + 5].hex(),
    }


def _load_method_starts(methods_csv: Path) -> tuple[list[int], dict[int, list[dict[str, str]]]]:
    by_rva: dict[int, list[dict[str, str]]] = {}
    with methods_csv.open("r", encoding="utf-8-sig", newline="") as f:
        for line_no, row in enumerate(csv.DictReader(f), start=2):
            text = str(row.get("rva", "")).strip()
            if not text:
                continue
            try:
                rva = int(text, 0)
            except ValueError as exc:
                raise ValueError(f"{methods_csv}:{line_no}: invalid method RVA {text!r}") from exc
            by_rva.setdefault(rva, []).append(dict(row))
    return sorted(by_rva), by_rva


def attach_caller_methods(
    call_rvas: list[int],
    methods_csv: Path,
    *,
    max_method_body: int = 0x10000,
) -> dict[int, list[dict[str, str]]]:
    """Conservatively map call sites to the nearest preceding metadata method.

    A call is attributed only when it lies before the next distinct method RVA
    and within max_method_body bytes of the candidate start. Duplicate metadata
    rows sharing a start RVA are retained as ambiguity.
    """

    if max_method_body <= 0:
        raise ValueError("max_method_body must be positive")
    starts, by_rva = _load_method_starts(methods_csv)
    result: dict[int, list[dict[str, str]]] = {}
    for call_rva in call_rvas:
        pos = bisect_right(starts, call_rva) - 1
        if pos < 0:
            result[call_rva] = []
            continue
        start = starts[pos]
        next_start = starts[pos + 1] if pos + 1 < len(starts) else None
        if call_rva - start >= max_method_body or (next_start is not None and call_rva >= next_start):
            result[call_rva] = []
            continue
        result[call_rva] = by_rva[start]
    return result


def scan_direct_call_xrefs(
    exe: Path,
    target_rvas: list[int],
    *,
    methods_csv: Path | None = None,
    max_method_body: int = 0x10000,
    window: int = 24,
) -> dict[str, object]:
    """Scan executable PE sections for exact E8 rel32 calls to target RVAs."""

    if window < 0:
        raise ValueError("window must be non-negative")
    targets = set(target_rvas)
    matches: dict[int, list[dict[str, object]]] = {target: [] for target in target_rvas}

    with PEImage(exe) as image:
        scanned_sections: list[str] = []
        call_sites: list[int] = []
        for section in image.sections:
            if not (section.characteristics & 0x20000000):
                continue
            blob = image.read_rva(section.virtual_address, section.raw_size)
            if not blob:
                continue
            scanned_sections.append(section.name)
            cursor = 0
            while True:
                offset = blob.find(b"\xE8", cursor)
                if offset < 0:
                    break
                cursor = offset + 1
                instruction_rva = section.virtual_address + offset
                decoded = decode_direct_call(blob, offset, instruction_rva)
                if decoded is None:
                    continue
                target_rva = int(decoded["target_rva"])
                if target_rva not in targets:
                    continue
                before = min(window, offset)
                start_rva = instruction_rva - before
                window_bytes = image.read_rva(start_rva, before + 5 + window)
                row: dict[str, object] = {
                    **decoded,
                    "section": section.name,
                    "window_rva": f"0x{start_rva:X}",
                    "window_hex": window_bytes.hex(),
                }
                matches[target_rva].append(row)
                call_sites.append(instruction_rva)

    callers: dict[int, list[dict[str, str]]] = {}
    if methods_csv is not None and call_sites:
        callers = attach_caller_methods(call_sites, methods_csv, max_method_body=max_method_body)

    formatted: dict[str, list[dict[str, object]]] = {}
    for target, rows in matches.items():
        formatted_rows = []
        for row in rows:
            site = int(row["instruction_rva"])
            formatted_rows.append(
                {
                    **row,
                    "instruction_rva": f"0x{site:X}",
                    "target_rva": f"0x{int(row['target_rva']):X}",
                    "caller_methods": callers.get(site, []),
                }
            )
        formatted[f"0x{target:X}"] = formatted_rows

    return {
        "targets": [f"0x{target:X}" for target in target_rvas],
        "methods_csv": None if methods_csv is None else str(methods_csv),
        "max_method_body": max_method_body,
        "scanned_sections": scanned_sections,
        "matches": formatted,
    }
