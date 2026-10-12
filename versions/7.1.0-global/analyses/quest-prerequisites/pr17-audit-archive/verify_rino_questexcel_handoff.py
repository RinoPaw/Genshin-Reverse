#!/usr/bin/env python3
"""Read-only audit of the 7.1 QuestExcel prerequisite handoff.

Arguments: upstream-dir candidate-dir play-rino-dir ref-3700-dir ref-4000-dir
No data is modified; this script does NOT certify 3.7 semantics as native 7.1.
"""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import sys

MAIN_IDS = (1008, 1011, 1013, 1016, 1018, 1019, 1021, 1029, 1030,
            2000, 2004, 2008, 2009, 8000, 8005, 8006)
EXCEL = Path("ExcelBinOutput/QuestExcelConfigData.json")
CANDIDATE_ALLOWED_KEYS = frozenset(("acceptCond", "acceptCondComb"))
UPSTREAM_ONLY_COMBINERS = frozenset((38301, 2010113, 2010123, 2010133))


def excel(root: Path) -> dict[int, dict]:
    rows = json.loads((root / EXCEL).read_text(encoding="utf-8"))
    assert isinstance(rows, list) and len(rows) == 33217, (root, len(rows))
    result = {int(row["subId"]): row for row in rows}
    assert len(result) == len(rows), f"{root} has duplicate subquest IDs"
    return result


def historical(root: Path) -> dict[int, dict]:
    result: dict[int, dict] = {}
    for main in MAIN_IDS:
        path = root / "BinOutput" / "Quest" / f"{main}.json"
        doc = json.loads(path.read_text(encoding="utf-8"))
        for row in doc["subQuests"]:
            sub = int(row["subId"])
            assert sub not in result, sub
            result[sub] = row
    return result


def cond_signature(value: object) -> list[tuple]:
    signature = []
    for cond in value or []:
        if not isinstance(cond, dict) or not cond.get("type"):
            continue
        params = [int(p) if isinstance(p, str) and p.lstrip("-").isdigit() else p
                  for p in cond.get("param", [])]
        if cond["type"] in ("QUEST_COND_STATE_EQUAL", "QUEST_COND_STATE_NOT_EQUAL"):
            while len(params) > 2 and params[-1] == 0:
                params.pop()
        signature.append((cond["type"], tuple(params)))
    return signature


def main() -> None:
    if len(sys.argv) != 6:
        raise SystemExit(f"Usage: {sys.argv[0]} UPSTREAM CANDIDATE RINO REF3700 REF4000")
    upstream_dir, candidate_dir, rino_dir, ref37_dir, ref40_dir = map(Path, sys.argv[1:])
    upstream, candidate, rino = map(excel, (upstream_dir, candidate_dir, rino_dir))
    assert set(upstream) == set(candidate) == set(rino)

    modifications = {}
    for sub_id, a in upstream.items():
        b = candidate[sub_id]
        if a == b:
            continue
        keys = {k for k in a.keys() | b.keys() if a.get(k) != b.get(k)}
        assert keys <= CANDIDATE_ALLOWED_KEYS, (sub_id, keys)
        modifications[sub_id] = sorted(keys)

    assert modifications, "No verified prerequisite changes"
    assert upstream[35301].get("finishExec") == candidate[35301].get("finishExec") == [], (
        "35301 early Amber grant regression"
    )
    assert all(candidate[sid].get("acceptCondComb") == upstream[sid].get("acceptCondComb")
               for sid in UPSTREAM_ONLY_COMBINERS), "Candidate regressed upstream logic combiners"

    refs37, refs40 = historical(ref37_dir), historical(ref40_dir)
    disputes = [
        sid for sid, old in rino.items()
        if old.get("acceptCondComb") and not upstream[sid].get("acceptCondComb")
        and old.get("acceptCondComb") != upstream[sid].get("acceptCondComb")
    ]
    assert len(disputes) == 34, ("unexpected number of historical combiner differences", len(disputes))
    summaries = []
    for sub in sorted(disputes):
        old, a, b = rino[sub], refs37.get(sub), refs40.get(sub)
        assert a and b, ("missing historical row", sub)
        comb = old["acceptCondComb"]
        assert a.get("acceptCondComb") == comb == b.get("acceptCondComb"), (
            "historical combo consensus missing", sub, comb,
            a.get("acceptCondComb"), b.get("acceptCondComb"),
        )
        old_conditions = cond_signature(old.get("acceptCond"))
        match37 = old_conditions == cond_signature(a.get("acceptCond"))
        match40 = old_conditions == cond_signature(b.get("acceptCond"))
        candidate_comb = candidate[sub].get("acceptCondComb")
        candidate_matches_historical = candidate_comb == comb
        summaries.append({
            "subId": sub, "mainId": old.get("mainId"),
            "combiner": comb,
            "rino_cond_matches_both_history": match37 and match40,
            "candidate_restored_combiner": candidate_matches_historical,
            "candidate_cond_matches_rino": cond_signature(candidate[sub].get("acceptCond")) == old_conditions,
        })

    result = {
        "population": len(upstream),
        "candidate_modified_rows": len(modifications),
        "candidate_field_changes": dict(Counter(
            key for keys in modifications.values() for key in keys
        )),
        "rino_only_combiners": len(disputes),
        "candidate_restored_historical_combiners": sum(
            v["candidate_restored_combiner"] for v in summaries
        ),
        "rino_conditions_match_two_historical_references": sum(
            v["rino_cond_matches_both_history"] for v in summaries
        ),
        "candidate_conditions_match_rino": sum(
            v["candidate_cond_matches_rino"] for v in summaries
        ),
    }
    print("HANDOFF_SUMMARY " + json.dumps(result, sort_keys=True))
    for item in summaries:
        print("COMBINER_EVIDENCE " + json.dumps(item, sort_keys=True))
    print("PASS read-only QuestExcel validation and two-reference combiner consensus")


if __name__ == "__main__":
    main()
