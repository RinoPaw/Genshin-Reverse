from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def _load(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def _ratio(matches: int, total: int) -> float | None:
    return None if total == 0 else matches / total


def audit_direction_flags(
    raw_registry_csv: Path,
    known_opcodes_csv: Path,
    output_json: Path | None = None,
    mismatch_limit: int = 200,
) -> dict[str, object]:
    raw_rows = _load(raw_registry_csv)
    known_rows = _load(known_opcodes_csv)

    flags_by_cmd: dict[int, int] = {}
    for row in raw_rows:
        try:
            cmd_id = int(str(row.get("cmd_id", "")), 0)
            flag = int(str(row.get("registry_flag", "")), 0)
        except ValueError:
            continue
        flags_by_cmd[cmd_id] = flag

    controls_by_name: dict[str, tuple[int, int]] = {}
    req_total = req_expected = 0
    rsp_total = rsp_expected = 0
    mismatches: list[dict[str, object]] = []

    for row in known_rows:
        name = str(row.get("semantic_name", "")).strip()
        try:
            cmd_id = int(str(row.get("cmd_id", "")), 0)
        except ValueError:
            continue
        flag = flags_by_cmd.get(cmd_id)
        if flag is None:
            continue
        controls_by_name[name] = (cmd_id, flag)

        expected = None
        semantic_direction = None
        if name.endswith("Req"):
            expected = 1
            semantic_direction = "C2S"
            req_total += 1
            if flag == expected:
                req_expected += 1
        elif name.endswith("Rsp"):
            expected = 0
            semantic_direction = "S2C"
            rsp_total += 1
            if flag == expected:
                rsp_expected += 1

        if expected is not None and flag != expected and len(mismatches) < mismatch_limit:
            mismatches.append(
                {
                    "semantic_name": name,
                    "cmd_id": cmd_id,
                    "registry_flag": flag,
                    "expected_flag_from_suffix": expected,
                    "semantic_direction": semantic_direction,
                }
            )

    pair_total = 0
    pair_consistent = 0
    pair_mismatches: list[dict[str, object]] = []
    for name, (req_cmd, req_flag) in sorted(controls_by_name.items()):
        if not name.endswith("Req"):
            continue
        stem = name[:-3]
        rsp_name = stem + "Rsp"
        rsp = controls_by_name.get(rsp_name)
        if rsp is None:
            continue
        rsp_cmd, rsp_flag = rsp
        pair_total += 1
        consistent = req_flag == 1 and rsp_flag == 0
        if consistent:
            pair_consistent += 1
        elif len(pair_mismatches) < mismatch_limit:
            pair_mismatches.append(
                {
                    "stem": stem,
                    "req": {"name": name, "cmd_id": req_cmd, "flag": req_flag},
                    "rsp": {"name": rsp_name, "cmd_id": rsp_cmd, "flag": rsp_flag},
                }
            )

    req_ratio = _ratio(req_expected, req_total)
    rsp_ratio = _ratio(rsp_expected, rsp_total)
    pair_ratio = _ratio(pair_consistent, pair_total)
    perfect_req_rsp = (
        req_total > 0
        and rsp_total > 0
        and req_expected == req_total
        and rsp_expected == rsp_total
    )
    perfect_pairs = pair_total > 0 and pair_consistent == pair_total

    result: dict[str, object] = {
        "raw_registry_rows": len(raw_rows),
        "raw_registry_unique_cmd_ids": len(flags_by_cmd),
        "known_opcode_rows": len(known_rows),
        "known_opcode_rows_joined": len(controls_by_name),
        "req_controls": req_total,
        "req_flag1_matches": req_expected,
        "req_flag1_ratio": req_ratio,
        "rsp_controls": rsp_total,
        "rsp_flag0_matches": rsp_expected,
        "rsp_flag0_ratio": rsp_ratio,
        "req_rsp_pairs": pair_total,
        "req_rsp_pairs_consistent": pair_consistent,
        "req_rsp_pair_consistency_ratio": pair_ratio,
        "perfect_req_rsp_suffix_agreement": perfect_req_rsp,
        "perfect_req_rsp_pair_agreement": perfect_pairs,
        "suffix_mismatch_count": (req_total - req_expected) + (rsp_total - rsp_expected),
        "suffix_mismatches": mismatches,
        "suffix_mismatches_truncated": ((req_total - req_expected) + (rsp_total - rsp_expected)) > len(mismatches),
        "pair_mismatch_count": pair_total - pair_consistent,
        "pair_mismatches": pair_mismatches,
        "pair_mismatches_truncated": (pair_total - pair_consistent) > len(pair_mismatches),
        "proposed_flag_mapping": {"1": "C2S", "0": "S2C"},
        "status": (
            "direction-mapping-strongly-validated"
            if perfect_req_rsp and perfect_pairs
            else "direction-mapping-audit-needed"
        ),
        "notes": [
            "only Req and Rsp suffixes are treated as directional semantic controls; Notify is excluded because notifications can be bidirectional in this protocol family",
            "Req/Rsp pairs are stronger controls than isolated names because both directions are observed for one semantic operation",
            "semantic names come from an independent server control set and remain subject to target-version correctness",
            "a non-perfect result should be investigated row by row before assigning global direction semantics",
        ],
    }
    if output_json is not None:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.directionaudit",
        description="Audit the 7.1 registry flag mapping against independent Req/Rsp semantic controls.",
    )
    parser.add_argument("raw_registry_csv", type=Path)
    parser.add_argument("known_opcodes_csv", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--mismatch-limit", type=int, default=200)
    parser.add_argument("--require-perfect", action="store_true")
    args = parser.parse_args()

    result = audit_direction_flags(
        args.raw_registry_csv,
        args.known_opcodes_csv,
        args.output,
        mismatch_limit=args.mismatch_limit,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if args.require_perfect and not (
        result["perfect_req_rsp_suffix_agreement"]
        and result["perfect_req_rsp_pair_agreement"]
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
