from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

HISTORICAL_REGISTRY_SCALE = 4_896


def _load_ids(path: Path) -> tuple[list[dict[str, str]], list[int]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    ids: list[int] = []
    for row in rows:
        text = str(row.get("cmd_id", "")).strip()
        if not text:
            continue
        try:
            value = int(text, 0)
        except ValueError:
            continue
        if value > 0:
            ids.append(value)
    return rows, ids


def diagnose_candidate_graph(
    graph_csv: Path,
    known_opcodes_csv: Path,
    output_json: Path | None = None,
) -> dict[str, object]:
    graph_rows, graph_id_rows = _load_ids(graph_csv)
    known_rows, known_id_rows = _load_ids(known_opcodes_csv)

    graph_counts = Counter(graph_id_rows)
    graph_ids = set(graph_counts)
    known_ids = set(known_id_rows)
    matched = sorted(graph_ids & known_ids)
    missing = sorted(known_ids - graph_ids)
    graph_only = sorted(graph_ids - known_ids)
    duplicates = {str(cmd_id): count for cmd_id, count in sorted(graph_counts.items()) if count > 1}

    coverage = (len(matched) / len(known_ids)) if known_ids else None
    result: dict[str, object] = {
        "graph_rows": len(graph_rows),
        "graph_unique_cmd_ids": len(graph_ids),
        "graph_duplicate_cmd_ids": duplicates,
        "control_rows": len(known_rows),
        "control_unique_cmd_ids": len(known_ids),
        "control_matched": len(matched),
        "control_missing_count": len(missing),
        "control_coverage": coverage,
        "control_missing_cmd_ids": missing,
        "graph_only_count": len(graph_only),
        "graph_only_cmd_ids": graph_only,
        "historical_registry_scale": HISTORICAL_REGISTRY_SCALE,
        "distance_from_historical_scale": len(graph_ids) - HISTORICAL_REGISTRY_SCALE,
        "all_control_ids_present": not missing,
        "status": (
            "strong-regression-signal"
            if not missing and len(graph_ids) == HISTORICAL_REGISTRY_SCALE
            else "candidate-diagnostic"
        ),
        "notes": [
            "graph-only CmdIds are not false positives by definition; the AstaPS control set is incomplete relative to the client registry",
            "missing control CmdIds indicate incomplete recovery or a version/control-set mismatch and should be investigated",
            "4,896 is preserved 7.1 audit evidence and is never used to trim or pad generated output",
        ],
    }

    if output_json is not None:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m genshinre.graphdiag",
        description="Compare a candidate registry graph with an independent known-opcode control set.",
    )
    parser.add_argument("graph_csv", type=Path)
    parser.add_argument("known_opcodes_csv", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-full-control", action="store_true")
    args = parser.parse_args()

    result = diagnose_candidate_graph(args.graph_csv, args.known_opcodes_csv, args.output)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if args.require_full_control and not result["all_control_ids_present"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
