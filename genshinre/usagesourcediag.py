from __future__ import annotations

import argparse
import csv
import hashlib
import json
import tempfile
from pathlib import Path

from .pe import PEImage
from .usagejoin import _load_runtime_types, _score_source_candidates, decode_source_value
from .usagesource import probe_usage_source_tables_71


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


def diagnose_usage_sources_71(
    exe: Path,
    usage_slots_csv: Path,
    runtime_types_csv: Path,
    getcmd_candidates_csv: Path,
    registry_type_slots_csv: Path,
    output_json: Path,
) -> dict[str, object]:
    slots = _rows(usage_slots_csv)
    runtime_types = _load_runtime_types(runtime_types_csv)
    getcmd_rows = _rows(getcmd_candidates_csv)
    registry_rows = _rows(registry_type_slots_csv)

    protocol_tdis = {
        tdi
        for row in getcmd_rows
        if str(row.get("method_name", "")) == "AEGNNPENLNM"
        if (tdi := _parse_int(row.get("type_definition_index"))) is not None
    }
    registry_slots = {
        slot
        for row in registry_rows
        if (slot := _parse_int(row.get("type_slot_rva"))) is not None
    }

    with tempfile.TemporaryDirectory() as td:
        probe = probe_usage_source_tables_71(exe, Path(td) / "usage-source-probe.json")

    type_array_va = int(str(probe["runtime_type_array_va"]), 0)
    diagnostics: list[dict[str, object]] = []
    with PEImage(exe) as image:
        scores = _score_source_candidates(image, probe, slots, runtime_types)
        for score in scores:
            table_rva = int(str(score["table_rva"]), 0)
            stride = int(score["stride"])
            width = int(score["width"])
            encoding = str(score["encoding"])

            protocol_rows = 0
            distinct_protocol_tdis: set[int] = set()
            registry_slot_rows = 0
            registry_slot_resolved_rows = 0
            registry_protocol_rows = 0
            registry_protocol_pairs: list[dict[str, object]] = []
            decoded_signature: list[tuple[int, int | None]] = []

            for slot_row in slots:
                usage_destination = _parse_int(slot_row.get("usage_destination"))
                if usage_destination is None:
                    continue
                slot_rva = _parse_int(slot_row.get("type_slot_rva"))
                is_registry_slot = slot_rva in registry_slots if slot_rva is not None else False
                if is_registry_slot:
                    registry_slot_rows += 1

                blob = image.read_rva(table_rva + usage_destination * stride, width)
                if len(blob) != width:
                    decoded_signature.append((usage_destination, None))
                    continue
                raw = int.from_bytes(blob, "little", signed=False)
                type_index, _ = decode_source_value(raw, encoding, type_array_va)
                decoded_signature.append((usage_destination, type_index))
                type_row = runtime_types.get(type_index) if type_index is not None else None
                if type_row is None:
                    continue

                if is_registry_slot:
                    registry_slot_resolved_rows += 1
                tdi = _parse_int(type_row.get("type_definition_index"))
                if tdi is not None and tdi in protocol_tdis:
                    protocol_rows += 1
                    distinct_protocol_tdis.add(tdi)
                    if is_registry_slot:
                        registry_protocol_rows += 1
                        if len(registry_protocol_pairs) < 30:
                            registry_protocol_pairs.append(
                                {
                                    "usage_destination": usage_destination,
                                    "type_slot_rva": f"0x{slot_rva:X}",
                                    "type_index": type_index,
                                    "type_definition_index": tdi,
                                    "type_name": str(type_row.get("type_name", "")),
                                }
                            )

            signature_bytes = json.dumps(decoded_signature, separators=(",", ":")).encode("utf-8")
            diagnostics.append(
                {
                    **score,
                    "protocol_candidate_rows": protocol_rows,
                    "distinct_protocol_candidate_types": len(distinct_protocol_tdis),
                    "registry_slot_rows": registry_slot_rows,
                    "registry_slot_resolved_rows": registry_slot_resolved_rows,
                    "registry_protocol_rows": registry_protocol_rows,
                    "registry_protocol_pairs": registry_protocol_pairs,
                    "decoded_signature_sha256": hashlib.sha256(signature_bytes).hexdigest(),
                }
            )

    diagnostics.sort(
        key=lambda row: (
            int(row["resolved_runtime_type_rows"]),
            int(row["distinct_resolved_types"]),
            float(row["resolved_ratio"]),
            int(row["registry_protocol_rows"]),
            int(row["protocol_candidate_rows"]),
        ),
        reverse=True,
    )
    result: dict[str, object] = {
        "usage_slot_rows": len(slots),
        "registry_type_slot_count": len(registry_slots),
        "protocol_candidate_type_count": len(protocol_tdis),
        "anchor_match_count": int(probe.get("anchor_match_count", 0)),
        "top_candidates": diagnostics[:30],
        "status": "diagnostic-only",
        "notes": [
            "ranking preserves runtime-type resolution as the primary signal",
            "registry_protocol_rows counts only call-site slots independently present in the verified 4,896-row constructor and decoded to AEGNNPENLNM GetCmdId candidate types",
            "this diagnostic does not select or publish a source table",
        ],
    }
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m genshinre.usagesourcediag")
    parser.add_argument("exe", type=Path)
    parser.add_argument("usage_slots_csv", type=Path)
    parser.add_argument("runtime_types_csv", type=Path)
    parser.add_argument("getcmd_candidates_csv", type=Path)
    parser.add_argument("registry_type_slots_csv", type=Path)
    parser.add_argument("output_json", type=Path)
    args = parser.parse_args()
    result = diagnose_usage_sources_71(
        args.exe,
        args.usage_slots_csv,
        args.runtime_types_csv,
        args.getcmd_candidates_csv,
        args.registry_type_slots_csv,
        args.output_json,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
