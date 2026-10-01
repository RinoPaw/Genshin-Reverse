from __future__ import annotations

import argparse
import bisect
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

from .pe import PEImage

COLUMNS = (
    "cmd_id",
    "type_name",
    "type_definition_index",
    "get_cmd_id_rva",
    "registry_slot_rva",
    "registry_index",
    "xref_count",
    "xref_method_count",
    "xref_methods",
    "candidate_slot_count",
    "status",
    "evidence",
)

ANCHORS = {
    9369: {"type_name": "DMMJNICDOHM", "registry_index": 2232, "registry_slot_rva": 0x057E6498},
    22899: {"type_name": "ONKOPMILDMF", "registry_index": 3118, "registry_slot_rva": 0x057F6F60},
}


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def _parse_int(value: object) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def recover_type_slot_xrefs_71(
    exe: Path,
    methods_csv: Path,
    getcmd_candidates_csv: Path,
    registry_type_slots_csv: Path,
    output_csv: Path,
    summary_json: Path | None = None,
    method_name: str = "AEGNNPENLNM",
    max_method_bytes: int = 0x2000,
) -> dict[str, object]:
    try:
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs
        from capstone.x86 import X86_OP_MEM, X86_REG_RIP
    except ImportError as exc:
        raise RuntimeError("typecachexref requires the capstone Python package") from exc

    method_rows = _rows(methods_csv)
    candidate_rows = [
        row for row in _rows(getcmd_candidates_csv) if str(row.get("method_name", "")) == method_name
    ]
    slot_rows = _rows(registry_type_slots_csv)

    slots: dict[int, int] = {}
    for row in slot_rows:
        slot = _parse_int(row.get("type_slot_rva"))
        index = _parse_int(row.get("index"))
        if slot is not None and index is not None:
            if slot in slots and slots[slot] != index:
                raise ValueError(f"registry slot 0x{slot:X} maps to multiple indices")
            slots[slot] = index
    if len(slot_rows) != 4896 or len(slots) != 4896:
        raise ValueError(f"expected 4,896 unique verified registry slots, got rows={len(slot_rows)} unique={len(slots)}")

    methods_by_type: dict[int, list[dict[str, str]]] = defaultdict(list)
    all_method_rvas: set[int] = set()
    for row in method_rows:
        tdi = _parse_int(row.get("type_definition_index"))
        rva = _parse_int(row.get("rva"))
        if rva is None:
            continue
        all_method_rvas.add(rva)
        if tdi is not None:
            methods_by_type[tdi].append(row)
    sorted_method_rvas = sorted(all_method_rvas)

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    emitted: list[dict[str, str]] = []
    types_with_any_registry_xref = 0
    types_with_unique_registry_xref = 0
    types_with_dominant_registry_xref = 0
    slot_owner_candidates: dict[int, list[dict[str, object]]] = defaultdict(list)

    with PEImage(exe) as image:
        for candidate in candidate_rows:
            tdi = _parse_int(candidate.get("type_definition_index"))
            cmd_id = _parse_int(candidate.get("cmd_id"))
            if tdi is None or cmd_id is None:
                continue

            hit_counts: Counter[int] = Counter()
            hit_methods: dict[int, set[str]] = defaultdict(set)
            for method in methods_by_type.get(tdi, []):
                rva = _parse_int(method.get("rva"))
                if rva is None:
                    continue
                pos = bisect.bisect_right(sorted_method_rvas, rva)
                next_rva = sorted_method_rvas[pos] if pos < len(sorted_method_rvas) else rva + max_method_bytes
                size = min(max(next_rva - rva, 1), max_method_bytes)
                blob = image.read_rva(rva, size)
                if not blob:
                    continue
                method_label = f"{method.get('method_name', '')}@0x{rva:X}"
                try:
                    instructions = md.disasm(blob, rva)
                    for insn in instructions:
                        for operand in insn.operands:
                            if operand.type != X86_OP_MEM or operand.mem.base != X86_REG_RIP:
                                continue
                            target = insn.address + insn.size + operand.mem.disp
                            if target in slots:
                                hit_counts[target] += 1
                                hit_methods[target].add(method_label)
                except Exception:
                    continue

            if not hit_counts:
                emitted.append(
                    {
                        "cmd_id": str(cmd_id),
                        "type_name": str(candidate.get("type_name", "")),
                        "type_definition_index": str(tdi),
                        "get_cmd_id_rva": str(candidate.get("get_cmd_id_rva", "")),
                        "registry_slot_rva": "",
                        "registry_index": "",
                        "xref_count": "0",
                        "xref_method_count": "0",
                        "xref_methods": "",
                        "candidate_slot_count": "0",
                        "status": "NO_REGISTRY_SLOT_XREF",
                        "evidence": "no RIP-relative method-body reference to a verified registry constructor type slot",
                    }
                )
                continue

            types_with_any_registry_xref += 1
            ordered = sorted(
                hit_counts,
                key=lambda slot: (hit_counts[slot], len(hit_methods[slot]), -slots[slot]),
                reverse=True,
            )
            top = ordered[0]
            top_score = (hit_counts[top], len(hit_methods[top]))
            tied_top = [slot for slot in ordered if (hit_counts[slot], len(hit_methods[slot])) == top_score]
            unique = len(ordered) == 1
            dominant = len(tied_top) == 1
            if unique:
                types_with_unique_registry_xref += 1
            if dominant:
                types_with_dominant_registry_xref += 1

            status = "UNIQUE_SLOT_XREF" if unique else ("DOMINANT_SLOT_XREF" if dominant else "AMBIGUOUS_SLOT_XREF")
            for rank, slot in enumerate(ordered):
                row_status = status if rank == 0 else "SECONDARY_SLOT_XREF"
                methods = sorted(hit_methods[slot])
                emitted.append(
                    {
                        "cmd_id": str(cmd_id),
                        "type_name": str(candidate.get("type_name", "")),
                        "type_definition_index": str(tdi),
                        "get_cmd_id_rva": str(candidate.get("get_cmd_id_rva", "")),
                        "registry_slot_rva": f"0x{slot:X}",
                        "registry_index": str(slots[slot]),
                        "xref_count": str(hit_counts[slot]),
                        "xref_method_count": str(len(methods)),
                        "xref_methods": "|".join(methods[:20]),
                        "candidate_slot_count": str(len(ordered)),
                        "status": row_status,
                        "evidence": "RIP-relative reference from methods declared on the GetCmdId candidate type to a verified 4,896-row registry constructor slot",
                    }
                )
                slot_owner_candidates[slot].append(
                    {
                        "cmd_id": cmd_id,
                        "type_name": str(candidate.get("type_name", "")),
                        "type_definition_index": tdi,
                        "xref_count": hit_counts[slot],
                        "xref_method_count": len(methods),
                        "rank": rank,
                    }
                )

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(emitted)

    anchor_results: dict[str, object] = {}
    for cmd_id, anchor in ANCHORS.items():
        rows = [row for row in emitted if _parse_int(row.get("cmd_id")) == cmd_id]
        expected_slot = int(anchor["registry_slot_rva"])
        exact = [row for row in rows if _parse_int(row.get("registry_slot_rva")) == expected_slot]
        top = next((row for row in rows if row.get("status") in {"UNIQUE_SLOT_XREF", "DOMINANT_SLOT_XREF", "AMBIGUOUS_SLOT_XREF"}), None)
        anchor_results[str(cmd_id)] = {
            "type_name": anchor["type_name"],
            "expected_registry_index": anchor["registry_index"],
            "expected_registry_slot_rva": f"0x{expected_slot:X}",
            "expected_slot_referenced": bool(exact),
            "top_slot_matches": top is not None and _parse_int(top.get("registry_slot_rva")) == expected_slot,
            "top": top,
        }

    slots_with_owner_candidates = len(slot_owner_candidates)
    slots_with_single_owner_candidate = sum(len(owners) == 1 for owners in slot_owner_candidates.values())
    summary: dict[str, object] = {
        "method_name_filter": method_name,
        "candidate_type_count": len(candidate_rows),
        "verified_registry_slot_count": len(slots),
        "types_with_any_registry_slot_xref": types_with_any_registry_xref,
        "types_with_unique_registry_slot_xref": types_with_unique_registry_xref,
        "types_with_dominant_registry_slot_xref": types_with_dominant_registry_xref,
        "slots_with_owner_candidates": slots_with_owner_candidates,
        "slots_with_single_owner_candidate": slots_with_single_owner_candidate,
        "anchors": anchor_results,
        "all_anchor_top_slots_match": all(bool(item["top_slot_matches"]) for item in anchor_results.values()),
        "status": "xref-diagnostic",
        "notes": [
            "constructor slots are independently verified; this artifact only asks whether methods declared on each GetCmdId candidate type reference those slots",
            "multiple slot references are retained and ranked by instruction count then distinct declaring-method count",
            "no row is promoted to canonical registry identity solely by this diagnostic",
        ],
    }
    if summary_json is None:
        summary_json = output_csv.with_suffix(".summary.json")
    summary_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m genshinre.typecachexref")
    parser.add_argument("exe", type=Path)
    parser.add_argument("methods_csv", type=Path)
    parser.add_argument("getcmd_candidates_csv", type=Path)
    parser.add_argument("registry_type_slots_csv", type=Path)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--method-name", default="AEGNNPENLNM")
    parser.add_argument("--max-method-bytes", type=lambda value: int(value, 0), default=0x2000)
    args = parser.parse_args()
    result = recover_type_slot_xrefs_71(
        args.exe,
        args.methods_csv,
        args.getcmd_candidates_csv,
        args.registry_type_slots_csv,
        args.output_csv,
        summary_json=args.summary,
        method_name=args.method_name,
        max_method_bytes=args.max_method_bytes,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
