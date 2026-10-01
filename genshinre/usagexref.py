from __future__ import annotations

import argparse
import bisect
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

from .pe import PEImage
from .usage import INITIALIZER_RVA_71

COLUMNS = (
    "usage_destination",
    "type_slot_rva",
    "cmd_id",
    "type_definition_index",
    "type_name",
    "method_rva",
    "method_name",
    "call_rva",
    "usage_load_rva",
    "slot_xref_rva",
    "slot_xref_distance",
    "status",
    "evidence",
)

PRIMARY_XREF_STATUSES = {"UNIQUE_SLOT_XREF", "DOMINANT_SLOT_XREF"}


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


def _xref_method_rvas(text: str) -> set[int]:
    result: set[int] = set()
    for part in text.split("|"):
        part = part.strip()
        if "@0x" not in part:
            continue
        try:
            result.add(int(part.rsplit("@0x", 1)[1], 16))
        except ValueError:
            continue
    return result


def recover_usage_xrefs_71(
    exe: Path,
    methods_csv: Path,
    type_cache_xrefs_csv: Path,
    output_csv: Path,
    summary_json: Path | None = None,
    search_before: int = 96,
    search_after: int = 128,
    max_method_bytes: int = 0x4000,
) -> dict[str, object]:
    try:
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs
        from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
    except ImportError as exc:
        raise RuntimeError("usagexref requires the capstone Python package") from exc

    method_rows = _rows(methods_csv)
    xref_rows = [row for row in _rows(type_cache_xrefs_csv) if row.get("status") in PRIMARY_XREF_STATUSES]
    if len(xref_rows) != 4896:
        raise ValueError(f"expected 4,896 primary type-cache xref rows, got {len(xref_rows)}")

    method_by_rva: dict[int, dict[str, str]] = {}
    all_rvas: set[int] = set()
    for row in method_rows:
        rva = _int(row.get("rva"))
        if rva is None:
            continue
        all_rvas.add(rva)
        method_by_rva.setdefault(rva, row)
    sorted_rvas = sorted(all_rvas)

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    evidence_rows: list[dict[str, str]] = []
    scanned_method_rvas: set[int] = set()
    per_type_usage: dict[int, Counter[int]] = defaultdict(Counter)
    per_type_best_distance: dict[tuple[int, int], int] = {}

    with PEImage(exe) as image:
        for xref in xref_rows:
            tdi = _int(xref.get("type_definition_index"))
            slot = _int(xref.get("registry_slot_rva"))
            cmd_id = _int(xref.get("cmd_id"))
            if tdi is None or slot is None or cmd_id is None:
                continue
            method_rvas = _xref_method_rvas(str(xref.get("xref_methods", "")))
            for method_rva in method_rvas:
                scanned_method_rvas.add(method_rva)
                pos = bisect.bisect_right(sorted_rvas, method_rva)
                next_rva = sorted_rvas[pos] if pos < len(sorted_rvas) else method_rva + max_method_bytes
                size = min(max(next_rva - method_rva, 1), max_method_bytes)
                blob = image.read_rva(method_rva, size)
                if not blob:
                    continue
                insns = list(md.disasm(blob, method_rva))
                if not insns:
                    continue

                slot_refs: list[tuple[int, int]] = []
                initializer_calls: list[tuple[int, int]] = []
                usage_loads: list[tuple[int, int]] = []
                for idx, insn in enumerate(insns):
                    for operand in insn.operands:
                        if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                            target = insn.address + insn.size + operand.mem.disp
                            if target == slot:
                                slot_refs.append((idx, insn.address))
                    if insn.mnemonic == "call" and insn.operands and insn.operands[0].type == X86_OP_IMM:
                        if int(insn.operands[0].imm) == INITIALIZER_RVA_71:
                            initializer_calls.append((idx, insn.address))
                    if insn.mnemonic == "mov" and len(insn.operands) == 2:
                        dst, src = insn.operands
                        if dst.type == X86_OP_REG and src.type == X86_OP_IMM:
                            reg = insn.reg_name(dst.reg)
                            if reg in {"ecx", "rcx"}:
                                usage_loads.append((idx, int(src.imm) & 0xFFFFFFFF))

                if not slot_refs or not initializer_calls or not usage_loads:
                    continue

                for call_idx, call_rva in initializer_calls:
                    load_candidates = [
                        (idx, value)
                        for idx, value in usage_loads
                        if idx < call_idx and call_rva - insns[idx].address <= search_before
                    ]
                    if not load_candidates:
                        continue
                    load_idx, usage_destination = max(load_candidates, key=lambda item: item[0])
                    slot_candidates = [
                        (idx, rva)
                        for idx, rva in slot_refs
                        if -search_before <= rva - call_rva <= search_after
                    ]
                    if not slot_candidates:
                        continue
                    slot_idx, slot_xref_rva = min(slot_candidates, key=lambda item: abs(item[1] - call_rva))
                    distance = abs(slot_xref_rva - call_rva)
                    per_type_usage[tdi][usage_destination] += 1
                    key = (tdi, usage_destination)
                    previous = per_type_best_distance.get(key)
                    if previous is None or distance < previous:
                        per_type_best_distance[key] = distance
                    method = method_by_rva.get(method_rva, {})
                    evidence_rows.append(
                        {
                            "usage_destination": str(usage_destination),
                            "type_slot_rva": f"0x{slot:X}",
                            "cmd_id": str(cmd_id),
                            "type_definition_index": str(tdi),
                            "type_name": str(xref.get("type_name", "")),
                            "method_rva": f"0x{method_rva:X}",
                            "method_name": str(method.get("method_name", "")),
                            "call_rva": f"0x{call_rva:X}",
                            "usage_load_rva": f"0x{insns[load_idx].address:X}",
                            "slot_xref_rva": f"0x{slot_xref_rva:X}",
                            "slot_xref_distance": str(distance),
                            "status": "CALL_SLOT_XREF_EVIDENCE",
                            "evidence": "same declaring method contains verified registry-slot RIP xref and direct metadata initializer call with nearest ECX/RCX immediate usage id",
                        }
                    )

    # Collapse only types where all qualifying observations agree on one usage id.
    stable_rows: list[dict[str, str]] = []
    ambiguous_types: list[dict[str, object]] = []
    for xref in xref_rows:
        tdi = _int(xref.get("type_definition_index"))
        slot = _int(xref.get("registry_slot_rva"))
        cmd_id = _int(xref.get("cmd_id"))
        if tdi is None or slot is None or cmd_id is None:
            continue
        counts = per_type_usage.get(tdi, Counter())
        if len(counts) == 1:
            usage_destination, observations = next(iter(counts.items()))
            stable_rows.append(
                {
                    "usage_destination": str(usage_destination),
                    "type_slot_rva": f"0x{slot:X}",
                    "cmd_id": str(cmd_id),
                    "type_definition_index": str(tdi),
                    "type_name": str(xref.get("type_name", "")),
                    "method_rva": "",
                    "method_name": "",
                    "call_rva": "",
                    "usage_load_rva": "",
                    "slot_xref_rva": "",
                    "slot_xref_distance": str(per_type_best_distance[(tdi, usage_destination)]),
                    "status": "STABLE_USAGE_TYPE_XREF",
                    "evidence": f"{observations} qualifying call/slot-xref observation(s), unanimous usage id for this verified protocol type",
                }
            )
        elif len(counts) > 1:
            ambiguous_types.append(
                {
                    "type_definition_index": tdi,
                    "type_name": str(xref.get("type_name", "")),
                    "cmd_id": cmd_id,
                    "type_slot_rva": f"0x{slot:X}",
                    "usage_candidates": [
                        {
                            "usage_destination": usage,
                            "observations": count,
                            "best_slot_distance": per_type_best_distance.get((tdi, usage)),
                        }
                        for usage, count in counts.most_common()
                    ],
                }
            )

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(stable_rows)

    usage_owners: dict[int, set[int]] = defaultdict(set)
    for row in stable_rows:
        usage_owners[int(row["usage_destination"])].add(int(row["type_definition_index"]))
    duplicate_usage_destinations = {
        str(usage): sorted(owners) for usage, owners in usage_owners.items() if len(owners) > 1
    }

    summary: dict[str, object] = {
        "protocol_type_count": len(xref_rows),
        "scanned_xref_method_count": len(scanned_method_rvas),
        "qualifying_call_slot_evidence_rows": len(evidence_rows),
        "stable_usage_type_rows": len(stable_rows),
        "ambiguous_type_count": len(ambiguous_types),
        "types_without_qualifying_usage_xref": len(xref_rows) - len(stable_rows) - len(ambiguous_types),
        "duplicate_usage_destinations_across_stable_types": duplicate_usage_destinations,
        "ambiguous_examples": ambiguous_types[:30],
        "anchors": {
            "9369": [row for row in stable_rows if row["cmd_id"] == "9369"],
            "22899": [row for row in stable_rows if row["cmd_id"] == "22899"],
        },
        "status": "static-xref-usage-map",
        "notes": [
            "this recovery does not use the legacy 37523 anchor as a selection rule",
            "a stable row requires the same managed method corridor to contain a verified type slot reference, direct initializer call, and immediate usage id",
            "ambiguous types are excluded rather than guessed",
        ],
    }
    if summary_json is None:
        summary_json = output_csv.with_suffix(".summary.json")
    summary_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m genshinre.usagexref")
    parser.add_argument("exe", type=Path)
    parser.add_argument("methods_csv", type=Path)
    parser.add_argument("type_cache_xrefs_csv", type=Path)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--search-before", type=int, default=96)
    parser.add_argument("--search-after", type=int, default=128)
    args = parser.parse_args()
    result = recover_usage_xrefs_71(
        args.exe,
        args.methods_csv,
        args.type_cache_xrefs_csv,
        args.output_csv,
        summary_json=args.summary,
        search_before=args.search_before,
        search_after=args.search_after,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
