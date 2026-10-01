from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

HISTORICAL_ROW_COUNT = 4_896


def _load(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def _slot_set(text: str) -> set[int]:
    result: set[int] = set()
    for part in text.split("|"):
        part = part.strip()
        if not part:
            continue
        try:
            result.add(int(part, 0))
        except ValueError:
            continue
    return result


def compare_raw_registries(
    direct_csv: Path,
    usage_csv: Path,
    output_json: Path | None = None,
    mismatch_limit: int = 200,
) -> dict[str, object]:
    direct = _load(direct_csv)
    usage = _load(usage_csv)

    direct_by_index: dict[int, dict[str, str]] = {}
    usage_by_index: dict[int, dict[str, str]] = {}
    for row in direct:
        try:
            direct_by_index[int(row["index"], 0)] = row
        except (KeyError, ValueError):
            continue
    for row in usage:
        try:
            usage_by_index[int(row["index"], 0)] = row
        except (KeyError, ValueError):
            continue

    all_indices = sorted(set(direct_by_index) | set(usage_by_index))
    cmd_matches = 0
    flag_matches = 0
    slot_matches = 0
    complete_matches = 0
    missing_direct: list[int] = []
    missing_usage: list[int] = []
    mismatches: list[dict[str, object]] = []

    for index in all_indices:
        d = direct_by_index.get(index)
        u = usage_by_index.get(index)
        if d is None:
            missing_direct.append(index)
            continue
        if u is None:
            missing_usage.append(index)
            continue

        cmd_equal = str(d.get("cmd_id", "")) == str(u.get("cmd_id", ""))
        flag_equal = str(d.get("registry_flag", "")) == str(u.get("registry_flag", ""))

        direct_slots = _slot_set(str(d.get("type_slot_rva", "")))
        usage_slots = _slot_set(str(u.get("type_slot_rvas", "")))
        slot_equal = bool(direct_slots) and direct_slots.issubset(usage_slots)

        if cmd_equal:
            cmd_matches += 1
        if flag_equal:
            flag_matches += 1
        if slot_equal:
            slot_matches += 1
        if cmd_equal and flag_equal and slot_equal:
            complete_matches += 1
        elif len(mismatches) < mismatch_limit:
            mismatches.append(
                {
                    "index": index,
                    "direct": {
                        "cmd_id": d.get("cmd_id", ""),
                        "registry_flag": d.get("registry_flag", ""),
                        "type_slot_rva": d.get("type_slot_rva", ""),
                    },
                    "usage_backed": {
                        "cmd_id": u.get("cmd_id", ""),
                        "registry_flag": u.get("registry_flag", ""),
                        "usage_destination": u.get("usage_destination", ""),
                        "type_slot_rvas": u.get("type_slot_rvas", ""),
                        "type_name": u.get("type_name", ""),
                    },
                    "cmd_match": cmd_equal,
                    "flag_match": flag_equal,
                    "slot_match": slot_equal,
                }
            )

    compared_rows = len(all_indices) - len(missing_direct) - len(missing_usage)
    exact_population = (
        len(direct_by_index) == HISTORICAL_ROW_COUNT
        and len(usage_by_index) == HISTORICAL_ROW_COUNT
        and len(all_indices) == HISTORICAL_ROW_COUNT
    )
    full_agreement = (
        exact_population
        and not missing_direct
        and not missing_usage
        and complete_matches == HISTORICAL_ROW_COUNT
    )

    result: dict[str, object] = {
        "direct_rows": len(direct_by_index),
        "usage_backed_rows": len(usage_by_index),
        "union_indices": len(all_indices),
        "compared_rows": compared_rows,
        "cmd_matches": cmd_matches,
        "flag_matches": flag_matches,
        "slot_matches": slot_matches,
        "complete_matches": complete_matches,
        "missing_direct_indices": missing_direct,
        "missing_usage_indices": missing_usage,
        "mismatch_count": compared_rows - complete_matches,
        "mismatches": mismatches,
        "mismatches_truncated": (compared_rows - complete_matches) > len(mismatches),
        "historical_row_count_reference": HISTORICAL_ROW_COUNT,
        "exact_population": exact_population,
        "full_agreement": full_agreement,
        "status": "independent-native-paths-agree" if full_agreement else "native-paths-not-closed",
        "notes": [
            "direct-slot and usage-backed exports arise from different structural hypotheses and are compared by native row index",
            "a direct slot matches a usage-backed row when it is contained in that usage destination's independently recovered slot set",
            "full agreement is a strong closure signal but semantic protobuf naming remains a separate evidence layer",
        ],
    }
    if output_json is not None:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.registrycompare",
        description="Compare independent direct-slot and usage-backed 7.1 native registry exports row by row.",
    )
    parser.add_argument("direct_csv", type=Path)
    parser.add_argument("usage_csv", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--mismatch-limit", type=int, default=200)
    parser.add_argument("--require-full-agreement", action="store_true")
    args = parser.parse_args()

    result = compare_raw_registries(
        args.direct_csv,
        args.usage_csv,
        args.output,
        mismatch_limit=args.mismatch_limit,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if args.require_full_agreement and not result["full_agreement"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
