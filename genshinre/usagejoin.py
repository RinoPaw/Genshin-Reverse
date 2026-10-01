from __future__ import annotations

import argparse
import csv
import json
import tempfile
from pathlib import Path

from .pe import PEImage
from .usagesource import (
    ANCHOR_TYPE_INDEX,
    LOW29_MASK,
    TYPE_ENTRY_SIZE,
    probe_usage_source_tables_71,
)

COLUMNS = (
    "usage_destination",
    "type_slot_rva",
    "raw_source",
    "source_encoding",
    "encoded_usage_kind",
    "type_index",
    "type_definition_index",
    "type_name",
    "status",
    "evidence",
)

ENCODINGS = (
    "direct-type-index",
    "low29-encoded-index",
    "runtime-type-entry-pointer",
)


def _load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def _load_runtime_types(path: Path) -> dict[int, dict[str, str]]:
    result: dict[int, dict[str, str]] = {}
    for row in _load_csv(path):
        try:
            result[int(row["type_index"])] = row
        except (KeyError, ValueError):
            continue
    return result


def decode_source_value(value: int, encoding: str, type_array_va: int) -> tuple[int | None, int | None]:
    if encoding == "direct-type-index":
        return value, None
    if encoding == "low29-encoded-index":
        return value & LOW29_MASK, (value >> 29) & 0x7
    if encoding == "runtime-type-entry-pointer":
        if value < type_array_va:
            return None, None
        delta = value - type_array_va
        if delta % TYPE_ENTRY_SIZE:
            return None, None
        return delta // TYPE_ENTRY_SIZE, None
    raise ValueError(f"unsupported source encoding: {encoding}")


def _select_anchor_match(matches: list[dict[str, object]]) -> tuple[dict[str, object], str] | None:
    normalized: list[tuple[dict[str, object], str]] = []
    for match in matches:
        for classification in list(match.get("classifications", [])):
            if int(classification.get("decoded_type_index", -1)) == ANCHOR_TYPE_INDEX:
                normalized.append((match, str(classification["kind"])))
    unique = {
        (str(item[0]["table_rva"]), int(item[0]["stride"]), int(item[0]["width"]), item[1])
        for item in normalized
    }
    if not unique:
        return None
    if len(unique) != 1:
        raise ValueError("metadata usage anchor matches multiple source tables or encodings")
    table_rva, stride, width, encoding = next(iter(unique))
    selected = next(
        item
        for item, kind in normalized
        if str(item["table_rva"]) == table_rva
        and int(item["stride"]) == stride
        and int(item["width"]) == width
        and kind == encoding
    )
    return selected, encoding


def _candidate_specs(probe: dict[str, object]) -> list[tuple[int, int, int, str]]:
    seen: set[tuple[int, int, int, str]] = set()
    result: list[tuple[int, int, int, str]] = []
    for item in list(probe.get("table_probes", [])):
        table_rva = int(str(item["table_rva"]), 0)
        stride = int(item["stride"])
        width = int(item["width"])
        for encoding in ENCODINGS:
            key = (table_rva, stride, width, encoding)
            if key not in seen:
                seen.add(key)
                result.append(key)
    return result


def _score_source_candidates(
    image: PEImage,
    probe: dict[str, object],
    slots: list[dict[str, str]],
    runtime_types: dict[int, dict[str, str]],
) -> list[dict[str, object]]:
    type_array_va = int(str(probe["runtime_type_array_va"]), 0)
    usage_ids: list[int] = []
    for slot in slots:
        try:
            usage_ids.append(int(slot["usage_destination"]))
        except (KeyError, ValueError):
            continue

    scores: list[dict[str, object]] = []
    for table_rva, stride, width, encoding in _candidate_specs(probe):
        readable = 0
        decoded = 0
        resolved = 0
        distinct_types: set[int] = set()
        for usage_destination in usage_ids:
            entry_rva = table_rva + usage_destination * stride
            blob = image.read_rva(entry_rva, width)
            if len(blob) != width:
                continue
            readable += 1
            raw = int.from_bytes(blob, "little", signed=False)
            type_index, _ = decode_source_value(raw, encoding, type_array_va)
            if type_index is None:
                continue
            decoded += 1
            if type_index in runtime_types:
                resolved += 1
                distinct_types.add(type_index)
        scores.append(
            {
                "table_rva": f"0x{table_rva:X}",
                "stride": stride,
                "width": width,
                "encoding": encoding,
                "usage_rows": len(usage_ids),
                "readable_rows": readable,
                "decoded_rows": decoded,
                "resolved_runtime_type_rows": resolved,
                "distinct_resolved_types": len(distinct_types),
                "resolved_ratio": 0.0 if readable == 0 else resolved / readable,
            }
        )
    scores.sort(
        key=lambda row: (
            int(row["resolved_runtime_type_rows"]),
            int(row["distinct_resolved_types"]),
            float(row["resolved_ratio"]),
        ),
        reverse=True,
    )
    return scores


def _physical_source_identity(row: dict[str, object]) -> tuple[str, int, int]:
    return str(row["table_rva"]), int(row["stride"]), int(row["width"])


def _decoded_signature(
    image: PEImage,
    probe: dict[str, object],
    slots: list[dict[str, str]],
    score: dict[str, object],
) -> tuple[tuple[int, int | None], ...]:
    table_rva = int(str(score["table_rva"]), 0)
    stride = int(score["stride"])
    width = int(score["width"])
    encoding = str(score["encoding"])
    type_array_va = int(str(probe["runtime_type_array_va"]), 0)
    result: list[tuple[int, int | None]] = []
    for slot in slots:
        try:
            usage_destination = int(slot["usage_destination"])
        except (KeyError, ValueError):
            continue
        blob = image.read_rva(table_rva + usage_destination * stride, width)
        if len(blob) != width:
            result.append((usage_destination, None))
            continue
        raw = int.from_bytes(blob, "little", signed=False)
        type_index, _ = decode_source_value(raw, encoding, type_array_va)
        result.append((usage_destination, type_index))
    return tuple(result)


def _select_globally_scored_source(
    image: PEImage,
    probe: dict[str, object],
    slots: list[dict[str, str]],
    runtime_types: dict[int, dict[str, str]],
) -> tuple[dict[str, object], str, list[dict[str, object]]]:
    scores = _score_source_candidates(image, probe, slots, runtime_types)
    if not scores:
        raise ValueError("metadata usage source probe exposed no candidate tables")
    best = scores[0]
    if int(best["resolved_runtime_type_rows"]) == 0:
        raise ValueError("metadata usage source candidates resolved zero runtime types")

    best_rank = (
        int(best["resolved_runtime_type_rows"]),
        int(best["distinct_resolved_types"]),
        float(best["resolved_ratio"]),
    )
    tied = [
        row
        for row in scores
        if (
            int(row["resolved_runtime_type_rows"]),
            int(row["distinct_resolved_types"]),
            float(row["resolved_ratio"]),
        )
        == best_rank
    ]
    if len(tied) > 1:
        physical_sources = {_physical_source_identity(row) for row in tied}
        if len(physical_sources) != 1:
            raise ValueError("metadata usage source global scoring produced an unresolved tie")
        signatures = {_decoded_signature(image, probe, slots, row) for row in tied}
        if len(signatures) != 1:
            raise ValueError("metadata usage source global scoring produced an unresolved tie")

    selected = {
        "table_rva": str(best["table_rva"]),
        "stride": int(best["stride"]),
        "width": int(best["width"]),
    }
    return selected, str(best["encoding"]), scores


def join_usage_sources_71(
    exe: Path,
    usage_slots_csv: Path,
    runtime_types_csv: Path,
    output_csv: Path,
    summary_json: Path | None = None,
    allow_unknown_sample: bool = False,
) -> dict[str, object]:
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    if summary_json is None:
        summary_json = output_csv.with_suffix(".summary.json")
    summary_json.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as td:
        probe_path = Path(td) / "usage-source-probe.json"
        probe = probe_usage_source_tables_71(
            exe,
            probe_path,
            allow_unknown_sample=allow_unknown_sample,
        )

    slots = _load_csv(usage_slots_csv)
    runtime_types = _load_runtime_types(runtime_types_csv)
    anchor_selection = _select_anchor_match(list(probe["anchor_matches"]))
    selection_basis = "preserved-anchor"
    candidate_scores: list[dict[str, object]] = []

    with PEImage(exe) as image:
        if anchor_selection is not None:
            selected, encoding = anchor_selection
        else:
            selection_basis = "global-runtime-type-resolution"
            selected, encoding, candidate_scores = _select_globally_scored_source(
                image,
                probe,
                slots,
                runtime_types,
            )

        table_rva = int(str(selected["table_rva"]), 0)
        stride = int(selected["stride"])
        width = int(selected["width"])
        type_array_va = int(str(probe["runtime_type_array_va"]), 0)

        resolved_type_rows = 0
        anchor_joined = False
        emitted = 0
        usage_kind_counts: dict[str, int] = {}

        with output_csv.open("w", encoding="utf-8", newline="") as out:
            writer = csv.DictWriter(out, fieldnames=COLUMNS)
            writer.writeheader()
            for slot in slots:
                try:
                    usage_destination = int(slot["usage_destination"])
                except (KeyError, ValueError):
                    continue
                entry_rva = table_rva + usage_destination * stride
                blob = image.read_rva(entry_rva, width)
                if len(blob) != width:
                    continue
                raw = int.from_bytes(blob, "little", signed=False)
                type_index, usage_kind = decode_source_value(raw, encoding, type_array_va)
                if usage_kind is not None:
                    key = str(usage_kind)
                    usage_kind_counts[key] = usage_kind_counts.get(key, 0) + 1
                type_row = runtime_types.get(type_index) if type_index is not None else None
                type_definition_index = "" if type_row is None else type_row.get("type_definition_index", "")
                type_name = "" if type_row is None else type_row.get("type_name", "")
                if type_row is not None:
                    resolved_type_rows += 1
                slot_rva = slot.get("type_slot_rva", "")
                if (
                    usage_destination == 37_523
                    and type_index == ANCHOR_TYPE_INDEX
                    and str(slot_rva).lower() == "0x57e6498"
                    and str(type_definition_index) == "84249"
                    and type_name == "DMMJNICDOHM"
                ):
                    anchor_joined = True
                writer.writerow(
                    {
                        "usage_destination": usage_destination,
                        "type_slot_rva": slot_rva,
                        "raw_source": f"0x{raw:X}",
                        "source_encoding": encoding,
                        "encoded_usage_kind": "" if usage_kind is None else usage_kind,
                        "type_index": "" if type_index is None else type_index,
                        "type_definition_index": type_definition_index,
                        "type_name": type_name,
                        "status": "static-decoded" if type_row is not None else "unresolved-source",
                        "evidence": f"joined initializer usage-slot evidence with {selection_basis} source table and runtime type index",
                    }
                )
                emitted += 1

    summary: dict[str, object] = {
        "exe": str(exe),
        "usage_slots_csv": str(usage_slots_csv),
        "runtime_types_csv": str(runtime_types_csv),
        "selection_basis": selection_basis,
        "selected_source_table": {
            "table_rva": f"0x{table_rva:X}",
            "stride": stride,
            "width": width,
            "encoding": encoding,
        },
        "candidate_scores": candidate_scores[:20],
        "usage_slot_rows": len(slots),
        "emitted_rows": emitted,
        "resolved_runtime_type_rows": resolved_type_rows,
        "encoded_usage_kind_counts": usage_kind_counts,
        "legacy_anchor_37523_to_405772_to_84249_DMMJNICDOHM": anchor_joined,
        "status": "static-joined" if resolved_type_rows else "candidate-joined",
        "notes": [
            "the historical 37523 anchor is diagnostic only; current artifacts can select a source table by global runtime-type resolution",
            "equivalent encoding labels are accepted only when they describe the same physical table and decode every observed usage destination to the same type index",
            "rows without a runtime type name may represent other metadata usage kinds or unresolved runtime type entries",
            "this artifact establishes metadata-usage/type identity and still does not by itself prove protocol registration",
        ],
    }
    summary_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if resolved_type_rows == 0:
        raise ValueError("joined usage source map resolved zero runtime types")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.usagejoin",
        description="Join 7.1 metadata usage slot/source tables to runtime IL2CPP types.",
    )
    parser.add_argument("exe", type=Path)
    parser.add_argument("usage_slots_csv", type=Path)
    parser.add_argument("runtime_types_csv", type=Path)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--allow-unknown-sample", action="store_true")
    args = parser.parse_args()

    result = join_usage_sources_71(
        args.exe,
        args.usage_slots_csv,
        args.runtime_types_csv,
        args.output_csv,
        summary_json=args.summary,
        allow_unknown_sample=args.allow_unknown_sample,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
