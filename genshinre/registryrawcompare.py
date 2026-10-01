from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def _slots(text: str) -> set[int]:
    result: set[int] = set()
    for part in str(text).split("|"):
        part = part.strip()
        if not part:
            continue
        result.add(int(part, 0))
    return result


def compare_native_registry_exports(
    direct_csv: Path,
    usage_csv: Path,
    output_json: Path,
    max_mismatches: int = 100,
) -> dict[str, object]:
    direct_rows = _rows(direct_csv)
    usage_rows = _rows(usage_csv)

    direct_by_index = {int(row["index"]): row for row in direct_rows}
    usage_by_index = {int(row["index"]): row for row in usage_rows}
    all_indices = sorted(set(direct_by_index) | set(usage_by_index))

    mismatches: list[dict[str, object]] = []
    missing_direct = 0
    missing_usage = 0
    slot_unresolved = 0
    slot_compared = 0
    slot_agree = 0

    for index in all_indices:
        direct = direct_by_index.get(index)
        usage = usage_by_index.get(index)
        if direct is None:
            missing_direct += 1
            if len(mismatches) < max_mismatches:
                mismatches.append({"index": index, "kind": "missing-direct"})
            continue
        if usage is None:
            missing_usage += 1
            if len(mismatches) < max_mismatches:
                mismatches.append({"index": index, "kind": "missing-usage"})
            continue

        row_errors: list[dict[str, object]] = []
        direct_cmd = int(direct["cmd_id"], 0)
        usage_cmd = int(usage["cmd_id"], 0)
        if direct_cmd != usage_cmd:
            row_errors.append({"field": "cmd_id", "direct": direct_cmd, "usage": usage_cmd})

        direct_flag = int(direct["registry_flag"], 0)
        usage_flag = int(usage["registry_flag"], 0)
        if direct_flag != usage_flag:
            row_errors.append({"field": "registry_flag", "direct": direct_flag, "usage": usage_flag})

        direct_slot = int(direct["type_slot_rva"], 0)
        usage_slots = _slots(usage.get("type_slot_rvas", ""))
        if usage_slots:
            slot_compared += 1
            if direct_slot in usage_slots:
                slot_agree += 1
            else:
                row_errors.append(
                    {
                        "field": "type_slot_rva",
                        "direct": f"0x{direct_slot:X}",
                        "usage": [f"0x{value:X}" for value in sorted(usage_slots)],
                    }
                )
        else:
            slot_unresolved += 1

        if row_errors and len(mismatches) < max_mismatches:
            mismatches.append(
                {
                    "index": index,
                    "cmd_id": direct_cmd,
                    "errors": row_errors,
                }
            )

    cmd_flag_mismatch_rows = sum(
        1
        for item in mismatches
        if item.get("errors")
        and any(error["field"] in {"cmd_id", "registry_flag"} for error in item["errors"])
    )
    slot_mismatch_rows = sum(
        1
        for item in mismatches
        if item.get("errors")
        and any(error["field"] == "type_slot_rva" for error in item["errors"])
    )

    full_row_coverage = (
        len(direct_rows) == len(usage_rows) == len(all_indices)
        and missing_direct == 0
        and missing_usage == 0
    )
    cmd_flag_agreement = full_row_coverage and cmd_flag_mismatch_rows == 0
    resolved_slot_agreement = slot_mismatch_rows == 0

    result: dict[str, object] = {
        "direct_rows": len(direct_rows),
        "usage_rows": len(usage_rows),
        "union_indices": len(all_indices),
        "missing_direct": missing_direct,
        "missing_usage": missing_usage,
        "slot_compared_rows": slot_compared,
        "slot_unresolved_rows": slot_unresolved,
        "slot_agree_rows": slot_agree,
        "cmd_flag_mismatch_rows": cmd_flag_mismatch_rows,
        "slot_mismatch_rows": slot_mismatch_rows,
        "full_row_coverage": full_row_coverage,
        "cmd_flag_agreement": cmd_flag_agreement,
        "resolved_slot_agreement": resolved_slot_agreement,
        "independent_exports_agree": cmd_flag_agreement and resolved_slot_agreement,
        "mismatches_truncated": len(mismatches) >= max_mismatches,
        "mismatches": mismatches,
        "status": "agree" if cmd_flag_agreement and resolved_slot_agreement else "disagree",
        "notes": [
            "CmdId and registry_flag are compared for every row index",
            "type-slot comparison is applied only where the usage-backed export resolves at least one slot",
            "agreement does not assign semantic protobuf names; it closes independent native layout evidence",
        ],
    }
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.registryrawcompare",
        description="Compare direct-slot and usage-backed 7.1 native registry exports row by row.",
    )
    parser.add_argument("direct_csv", type=Path)
    parser.add_argument("usage_csv", type=Path)
    parser.add_argument("output_json", type=Path)
    parser.add_argument("--max-mismatches", type=int, default=100)
    parser.add_argument("--require-agreement", action="store_true")
    args = parser.parse_args()

    result = compare_native_registry_exports(
        args.direct_csv,
        args.usage_csv,
        args.output_json,
        max_mismatches=args.max_mismatches,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if args.require_agreement and not result["independent_exports_agree"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
