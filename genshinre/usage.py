from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Iterator

from .pe import PEImage
from .xrefs import decode_simple_rip_relative

INITIALIZER_RVA_71 = 0x00523400
EXPECTED_DIRECT_CALLS_71 = 430_749
EXPECTED_IMMEDIATE_CALLS_71 = 430_737
EXPECTED_UNIQUE_USAGE_IDS_71 = 311_716

ANCHOR_9369 = {
    "usage_destination": 37_523,
    "store_rva": 0x07F852AB,
    "type_slot_rva": 0x057E6498,
}

USAGE_COLUMNS = (
    "usage_destination",
    "usage_hex",
    "mov_rva",
    "mov_pattern",
    "gap_before_call",
    "call_rva",
    "initializer_rva",
    "store_rva",
    "type_slot_rva",
    "store_hex",
    "section",
    "status",
    "evidence",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def decode_rel32_call(code: bytes, offset: int, instruction_rva: int) -> dict[str, object] | None:
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


def decode_mov_ecx_immediate(code: bytes, offset: int, instruction_rva: int) -> dict[str, object] | None:
    """Recognize conservative Windows-x64 first-argument immediate loads.

    The preserved audit describes direct `mov ecx, IMM` sources before calls to the
    7.1 metadata-usage initializer. We deliberately recognize only immediate ECX/RCX
    forms here; this is a recovery primitive, not a general x86 decoder.
    """

    if offset < 0 or offset >= len(code):
        return None

    if offset + 5 <= len(code) and code[offset] == 0xB9:
        value = int.from_bytes(code[offset + 1 : offset + 5], "little", signed=False)
        return {
            "instruction_rva": instruction_rva,
            "value": value,
            "length": 5,
            "pattern": "mov-ecx-imm32",
            "instruction_hex": code[offset : offset + 5].hex(),
        }

    if offset + 6 <= len(code) and code[offset : offset + 2] == b"\xC7\xC1":
        value = int.from_bytes(code[offset + 2 : offset + 6], "little", signed=False)
        return {
            "instruction_rva": instruction_rva,
            "value": value,
            "length": 6,
            "pattern": "mov-ecx-imm32-c7",
            "instruction_hex": code[offset : offset + 6].hex(),
        }

    if offset + 7 <= len(code) and code[offset : offset + 3] == b"\x48\xC7\xC1":
        value = int.from_bytes(code[offset + 3 : offset + 7], "little", signed=False)
        return {
            "instruction_rva": instruction_rva,
            "value": value,
            "length": 7,
            "pattern": "mov-rcx-imm32-c7",
            "instruction_hex": code[offset : offset + 7].hex(),
        }

    if offset + 10 <= len(code) and code[offset : offset + 2] == b"\x48\xB9":
        value = int.from_bytes(code[offset + 2 : offset + 10], "little", signed=False)
        return {
            "instruction_rva": instruction_rva,
            "value": value,
            "length": 10,
            "pattern": "mov-rcx-imm64",
            "instruction_hex": code[offset : offset + 10].hex(),
        }

    return None


def _nearest_usage_load(code: bytes, call_offset: int, base_rva: int, search_back: int) -> dict[str, object] | None:
    start = max(0, call_offset - search_back)
    best: dict[str, object] | None = None
    for offset in range(start, call_offset):
        decoded = decode_mov_ecx_immediate(code, offset, base_rva + offset)
        if decoded is None:
            continue
        end = offset + int(decoded["length"])
        if end > call_offset:
            continue
        decoded["gap_before_call"] = call_offset - end
        if best is None or int(decoded["instruction_rva"]) > int(best["instruction_rva"]):
            best = decoded
    return best


def _writes_after_call(code: bytes, call_offset: int, base_rva: int, search_after: int) -> list[dict[str, object]]:
    start = call_offset + 5
    end = min(len(code), start + search_after)
    writes: list[dict[str, object]] = []
    offset = start
    while offset < end:
        decoded = decode_simple_rip_relative(code, offset, base_rva + offset)
        if decoded is None:
            offset += 1
            continue
        length = int(decoded["length"])
        if decoded["access"] == "write":
            writes.append(decoded)
        offset += max(1, length)
    return writes


def iter_usage_call_records(
    code: bytes,
    base_rva: int,
    section_name: str,
    initializer_rva: int = INITIALIZER_RVA_71,
    search_back: int = 24,
    search_after: int = 32,
) -> Iterator[dict[str, object]]:
    """Yield one or more evidence records for each direct initializer call.

    A call with several nearby RIP-relative writes yields several records. A call with
    no recognized write still yields one record with blank store fields so aggregate
    call counts can be reproduced without retaining the whole executable in memory.
    """

    offset = 0
    while True:
        offset = code.find(b"\xE8", offset)
        if offset < 0:
            return
        call_rva = base_rva + offset
        call = decode_rel32_call(code, offset, call_rva)
        offset += 1
        if call is None or int(call["target_rva"]) != initializer_rva:
            continue

        usage = _nearest_usage_load(code, offset - 1, base_rva, search_back)
        stores = _writes_after_call(code, offset - 1, base_rva, search_after)
        if not stores:
            stores = [None]

        for store_index, store in enumerate(stores):
            usage_value = None if usage is None else int(usage["value"])
            record: dict[str, object] = {
                "usage_destination": "" if usage_value is None else usage_value,
                "usage_hex": "" if usage_value is None else f"0x{usage_value:X}",
                "mov_rva": "" if usage is None else f"0x{int(usage['instruction_rva']):X}",
                "mov_pattern": "" if usage is None else str(usage["pattern"]),
                "gap_before_call": "" if usage is None else int(usage["gap_before_call"]),
                "call_rva": f"0x{call_rva:X}",
                "initializer_rva": f"0x{initializer_rva:X}",
                "store_rva": "" if store is None else f"0x{int(store['instruction_rva']):X}",
                "type_slot_rva": "" if store is None else f"0x{int(store['target_rva']):X}",
                "store_hex": "" if store is None else str(store["instruction_hex"]),
                "section": section_name,
                "status": "CANDIDATE",
                "evidence": "direct initializer call + nearby immediate + RIP-relative write",
                "_first_for_call": store_index == 0,
                "_has_usage": usage is not None,
                "_has_store": store is not None,
            }
            yield record


def scan_usage_initializer_71(
    exe: Path,
    output_csv: Path,
    summary_json: Path | None = None,
    search_back: int = 24,
    search_after: int = 32,
    emit_all_calls: bool = False,
) -> dict[str, object]:
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    if summary_json is None:
        summary_json = output_csv.with_suffix(".summary.json")
    summary_json.parent.mkdir(parents=True, exist_ok=True)

    direct_calls = 0
    calls_with_immediate = 0
    calls_with_rip_store = 0
    emitted_rows = 0
    unique_usage_ids: set[int] = set()
    anchor_found = False
    scanned_sections: list[str] = []

    with output_csv.open("w", encoding="utf-8", newline="") as out, PEImage(exe) as image:
        writer = csv.DictWriter(out, fieldnames=USAGE_COLUMNS)
        writer.writeheader()
        for section in image.sections:
            if not (section.characteristics & 0x20000000):
                continue
            code = image.read_rva(section.virtual_address, section.raw_size)
            if not code:
                continue
            scanned_sections.append(section.name)
            for record in iter_usage_call_records(
                code,
                section.virtual_address,
                section.name,
                initializer_rva=INITIALIZER_RVA_71,
                search_back=search_back,
                search_after=search_after,
            ):
                if bool(record.pop("_first_for_call")):
                    direct_calls += 1
                    if bool(record["_has_usage"]):
                        calls_with_immediate += 1
                    if bool(record["_has_store"]):
                        calls_with_rip_store += 1
                has_usage = bool(record.pop("_has_usage"))
                has_store = bool(record.pop("_has_store"))
                if has_usage:
                    unique_usage_ids.add(int(record["usage_destination"]))
                if (
                    has_usage
                    and has_store
                    and int(record["usage_destination"]) == ANCHOR_9369["usage_destination"]
                    and int(str(record["store_rva"]), 0) == ANCHOR_9369["store_rva"]
                    and int(str(record["type_slot_rva"]), 0) == ANCHOR_9369["type_slot_rva"]
                ):
                    anchor_found = True
                if emit_all_calls or (has_usage and has_store):
                    writer.writerow({key: record[key] for key in USAGE_COLUMNS})
                    emitted_rows += 1

    summary: dict[str, object] = {
        "exe": str(exe),
        "exe_sha256": _sha256(exe),
        "initializer_rva": f"0x{INITIALIZER_RVA_71:X}",
        "search_back": search_back,
        "search_after": search_after,
        "scanned_sections": scanned_sections,
        "direct_calls": direct_calls,
        "calls_with_immediate": calls_with_immediate,
        "calls_with_rip_store": calls_with_rip_store,
        "unique_usage_ids": len(unique_usage_ids),
        "emitted_rows": emitted_rows,
        "emit_all_calls": emit_all_calls,
        "anchor_9369_usage_store_slot": anchor_found,
        "preserved_regression_counts": {
            "direct_calls": EXPECTED_DIRECT_CALLS_71,
            "calls_with_immediate": EXPECTED_IMMEDIATE_CALLS_71,
            "unique_usage_ids": EXPECTED_UNIQUE_USAGE_IDS_71,
        },
        "regression_matches": {
            "direct_calls": direct_calls == EXPECTED_DIRECT_CALLS_71,
            "calls_with_immediate": calls_with_immediate == EXPECTED_IMMEDIATE_CALLS_71,
            "unique_usage_ids": len(unique_usage_ids) == EXPECTED_UNIQUE_USAGE_IDS_71,
        },
        "status": "candidate-evidence",
        "notes": [
            "RIP-relative store recovery is deliberately narrow and may miss other instruction forms",
            "this output maps initializer-call evidence to slots; it is not the protocol registry",
            "the preserved counts are audit anchors and must not be forced into generated output",
        ],
    }
    summary_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.usage",
        description="Recover 7.1 metadata-usage initializer calls and nearby type-slot stores.",
    )
    parser.add_argument("exe", type=Path)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--search-back", type=int, default=24)
    parser.add_argument("--search-after", type=int, default=32)
    parser.add_argument("--all-calls", action="store_true")
    parser.add_argument("--require-9369-anchor", action="store_true")
    args = parser.parse_args()

    summary = scan_usage_initializer_71(
        args.exe,
        args.output_csv,
        summary_json=args.summary,
        search_back=args.search_back,
        search_after=args.search_after,
        emit_all_calls=args.all_calls,
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    if args.require_9369_anchor and not summary["anchor_9369_usage_store_slot"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
