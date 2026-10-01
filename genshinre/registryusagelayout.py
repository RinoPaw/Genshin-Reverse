from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from .mhy71 import EXPECTED_EXE_SHA256, _sha256
from .pe import PEImage
from .registrylayout import (
    ANCHOR_22899,
    ANCHOR_22899_INDEX_CANDIDATES,
    ANCHOR_9369,
    HISTORICAL_ROW_COUNT,
    RowAnchor,
    _column_metrics,
    _find_value_occurrences,
    _flag_field_matches,
    _read_uint,
)


def _load_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def resolve_anchor_usage_destinations(usage_types_csv: Path) -> dict[int, int]:
    rows = _load_rows(usage_types_csv)
    result: dict[int, int] = {}
    for anchor in (ANCHOR_9369, ANCHOR_22899):
        matches: set[int] = set()
        for row in rows:
            if str(row.get("type_name", "")) != anchor.name.split(" / ")[-1]:
                continue
            try:
                slot = int(str(row.get("type_slot_rva", "")), 0)
                usage = int(str(row.get("usage_destination", "")), 0)
            except ValueError:
                continue
            if slot == anchor.type_slot_rva:
                matches.add(usage)
        if len(matches) != 1:
            raise ValueError(
                f"anchor {anchor.cmd_id} / {anchor.name} resolved to {len(matches)} usage destinations; expected 1"
            )
        result[anchor.cmd_id] = next(iter(matches))

    if result[9369] != 37_523:
        raise ValueError(f"preserved 9369 usage destination changed: {result[9369]}")
    return result


def _usage_field_matches(
    image: PEImage,
    cmd1_rva: int,
    cmd2_rva: int,
    stride: int,
    usage1: int,
    usage2: int,
) -> list[dict[str, object]]:
    matches: list[dict[str, object]] = []
    for relative in range(-(stride - 1), stride):
        if _read_uint(image, cmd1_rva + relative, 4) != usage1:
            continue
        if _read_uint(image, cmd2_rva + relative, 4) != usage2:
            continue
        matches.append({"relative_to_cmd": relative, "width": 4})
    return matches


def _usage_column_metrics(
    image: PEImage,
    column_base_rva: int,
    stride: int,
    row_count: int,
    known_usage_destinations: set[int],
) -> dict[str, object]:
    readable = 0
    resolved = 0
    values: list[int] = []
    for index in range(row_count):
        value = _read_uint(image, column_base_rva + index * stride, 4)
        if value is None:
            break
        readable += 1
        values.append(value)
        if value in known_usage_destinations:
            resolved += 1
    return {
        "readable_rows": readable,
        "resolved_rows": resolved,
        "resolved_ratio": (resolved / readable) if readable else 0.0,
        "unique_values": len(set(values)),
    }


def _flag_column_metrics(
    image: PEImage,
    column_base_rva: int,
    stride: int,
    width: int,
    row_count: int,
) -> dict[str, object]:
    readable = 0
    binary = 0
    counts = {"0": 0, "1": 0, "other": 0}
    for index in range(row_count):
        value = _read_uint(image, column_base_rva + index * stride, width)
        if value is None:
            break
        readable += 1
        if value in (0, 1):
            binary += 1
            counts[str(value)] += 1
        else:
            counts["other"] += 1
    return {
        "readable_rows": readable,
        "binary_rows": binary,
        "binary_ratio": (binary / readable) if readable else 0.0,
        "counts": counts,
    }


def infer_usage_layout_candidates(
    image: PEImage,
    usage_destinations: dict[int, int],
    known_usage_destinations: set[int],
    anchor1: RowAnchor = ANCHOR_9369,
    anchor2_indices: tuple[int, ...] = ANCHOR_22899_INDEX_CANDIDATES,
    min_stride: int = 4,
    max_stride: int = 96,
    row_count: int = HISTORICAL_ROW_COUNT,
) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []

    for cmd_width in (2, 4):
        occurrences = _find_value_occurrences(image, anchor1.cmd_id, cmd_width)
        for occurrence in occurrences:
            cmd1_rva = int(occurrence["rva"])
            for index2 in anchor2_indices:
                anchor2 = RowAnchor(
                    index=index2,
                    cmd_id=ANCHOR_22899.cmd_id,
                    registry_flag=ANCHOR_22899.registry_flag,
                    type_slot_rva=ANCHOR_22899.type_slot_rva,
                    name=ANCHOR_22899.name,
                )
                delta_index = anchor2.index - anchor1.index
                if delta_index <= 0:
                    continue
                for stride in range(min_stride, max_stride + 1):
                    cmd2_rva = cmd1_rva + delta_index * stride
                    if _read_uint(image, cmd2_rva, cmd_width) != anchor2.cmd_id:
                        continue
                    cmd_column_base = cmd1_rva - anchor1.index * stride
                    if image.rva_to_offset(cmd_column_base) is None:
                        continue

                    usage_matches = _usage_field_matches(
                        image,
                        cmd1_rva,
                        cmd2_rva,
                        stride,
                        usage_destinations[anchor1.cmd_id],
                        usage_destinations[anchor2.cmd_id],
                    )
                    flag_matches = _flag_field_matches(
                        image, cmd1_rva, cmd2_rva, stride, anchor1, anchor2
                    )
                    if not usage_matches or not flag_matches:
                        continue

                    cmd_metrics = _column_metrics(
                        image, cmd_column_base, stride, cmd_width, row_count
                    )
                    for usage_match in usage_matches:
                        usage_relative = int(usage_match["relative_to_cmd"])
                        usage_metrics = _usage_column_metrics(
                            image,
                            cmd_column_base + usage_relative,
                            stride,
                            row_count,
                            known_usage_destinations,
                        )
                        for flag_match in flag_matches:
                            flag_relative = int(flag_match["relative_to_cmd"])
                            flag_width = int(flag_match["width"])
                            flag_metrics = _flag_column_metrics(
                                image,
                                cmd_column_base + flag_relative,
                                stride,
                                flag_width,
                                row_count,
                            )
                            score = (
                                float(cmd_metrics["protocol_range_ratio"]) * 25
                                + float(cmd_metrics["unique_ratio"]) * 25
                                + float(usage_metrics["resolved_ratio"]) * 25
                                + float(flag_metrics["binary_ratio"]) * 25
                                + (20 if int(cmd_metrics["unique_nonzero_values"]) == row_count else 0)
                            )
                            candidates.append(
                                {
                                    "score": score,
                                    "cmd_width": cmd_width,
                                    "stride": stride,
                                    "anchor_22899_index_interpretation": index2,
                                    "cmd_column_base_rva": f"0x{cmd_column_base:X}",
                                    "anchor_9369_cmd_rva": f"0x{cmd1_rva:X}",
                                    "anchor_22899_cmd_rva": f"0x{cmd2_rva:X}",
                                    "section": occurrence["section"],
                                    "usage_field": usage_match,
                                    "flag_field": flag_match,
                                    "cmd_metrics": cmd_metrics,
                                    "usage_metrics": usage_metrics,
                                    "flag_metrics": flag_metrics,
                                    "status": "usage-layout-candidate",
                                }
                            )

    deduped: dict[tuple[object, ...], dict[str, object]] = {}
    for item in candidates:
        key = (
            item["cmd_column_base_rva"],
            item["cmd_width"],
            item["stride"],
            item["anchor_22899_index_interpretation"],
            item["usage_field"]["relative_to_cmd"],
            item["flag_field"]["relative_to_cmd"],
            item["flag_field"]["width"],
        )
        previous = deduped.get(key)
        if previous is None or float(item["score"]) > float(previous["score"]):
            deduped[key] = item

    return sorted(deduped.values(), key=lambda item: float(item["score"]), reverse=True)


def probe_usage_registry_layout_71(
    exe: Path,
    usage_types_csv: Path,
    output_json: Path,
    allow_unknown_sample: bool = False,
    max_results: int = 100,
) -> dict[str, object]:
    exe_sha = _sha256(exe)
    if not allow_unknown_sample and exe_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"unexpected GenshinImpact.exe SHA-256: {exe_sha}")

    usage_destinations = resolve_anchor_usage_destinations(usage_types_csv)
    usage_rows = _load_rows(usage_types_csv)
    known_usage_destinations = {
        int(str(row["usage_destination"]), 0)
        for row in usage_rows
        if str(row.get("usage_destination", "")).strip()
    }

    with PEImage(exe) as image:
        candidates = infer_usage_layout_candidates(
            image,
            usage_destinations,
            known_usage_destinations,
        )

    strong = [
        item
        for item in candidates
        if int(item["cmd_metrics"]["unique_nonzero_values"]) == HISTORICAL_ROW_COUNT
        and float(item["cmd_metrics"]["protocol_range_ratio"]) == 1.0
        and float(item["flag_metrics"]["binary_ratio"]) == 1.0
        and float(item["usage_metrics"]["resolved_ratio"]) >= 0.99
    ]
    result: dict[str, object] = {
        "exe": str(exe),
        "exe_sha256": exe_sha,
        "historical_row_count_reference": HISTORICAL_ROW_COUNT,
        "anchor_usage_destinations": {
            str(key): value for key, value in sorted(usage_destinations.items())
        },
        "candidate_count": len(candidates),
        "strong_candidate_count": len(strong),
        "strong_unique": len(strong) == 1,
        "candidates": candidates[:max_results],
        "status": "strong-usage-layout-candidate" if len(strong) == 1 else "usage-layout-probe",
        "notes": [
            "this probe tests the hypothesis that the compact protocol table stores metadata usage destinations rather than expanded type-slot pointers",
            "9369 uses preserved row index 2232; 22899 tests both 3118 and 3117 index interpretations",
            "flag semantics are anchored by 9369=1/C2S and 22899=0/S2C but stay provisional until the table is independently closed",
            "no candidate is promoted to canonical registry data solely from this probe",
        ],
    }
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.registryusagelayout",
        description="Probe a compact 7.1 protocol registry that stores metadata usage destinations.",
    )
    parser.add_argument("exe", type=Path)
    parser.add_argument("usage_types_csv", type=Path)
    parser.add_argument("output_json", type=Path)
    parser.add_argument("--allow-unknown-sample", action="store_true")
    parser.add_argument("--max-results", type=int, default=100)
    parser.add_argument("--require-strong", action="store_true")
    args = parser.parse_args()

    result = probe_usage_registry_layout_71(
        args.exe,
        args.usage_types_csv,
        args.output_json,
        allow_unknown_sample=args.allow_unknown_sample,
        max_results=args.max_results,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if args.require_strong and int(result["strong_candidate_count"]) == 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
