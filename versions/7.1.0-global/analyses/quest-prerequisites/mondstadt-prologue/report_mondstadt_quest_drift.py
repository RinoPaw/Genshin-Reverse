#!/usr/bin/env python3
"""Report historical-compatibility Quest prerequisites versus flattened Excel.

This is evidence discovery: it does not claim native 7.1 acceptCond ownership
and does not rewrite either dataset.
"""
import json
from collections import Counter
from pathlib import Path
from audit_mondstadt_prologue import SCOPE


def normalize(conds):
    rows = []
    for c in conds or []:
        kind = c.get("type")
        if not kind:
            continue
        param = list(c.get("param") or [])
        # Historical 3-element state conditions pad their last integer with zero.
        if kind in ("QUEST_COND_STATE_EQUAL", "QUEST_COND_STATE_NOT_EQUAL") and len(param) == 3 and param[2] == 0:
            param = param[:2]
        rows.append({"type": kind, "param": param,
                     "param_str": c.get("param_str", c.get("_param_str", "")) or ""})
    return rows


def classify_accept(compat, excel, compat_comb, excel_comb):
    if not compat:
        return "no_compatibility_evidence"
    if compat == excel and compat_comb == excel_comb:
        return None
    if compat == excel:
        return "combinator_disagreement"
    if not excel or (len(excel) == 1
                     and excel[0]["type"] == "QUEST_COND_STATE_EQUAL"
                     and excel[0]["param"][:2] == [0, 3]):
        return "excel_placeholder"
    return "accept_disagreement"


def main():
    excel = {
        row["subId"]: row
        for row in json.loads(Path("ExcelBinOutput/QuestExcelConfigData.json").read_text(encoding="utf-8"))
        if isinstance(row, dict) and isinstance(row.get("subId"), int)
    }
    results, counts = [], Counter()
    for stage, ids in SCOPE.items():
        for main_id in ids:
            quest = json.loads(Path("BinOutput/Quest/%d.json" % main_id).read_text(encoding="utf-8"))
            for row in quest["subQuests"]:
                sub = row["subId"]
                current = excel.get(sub)
                if current is None:
                    results.append({"stage": stage, "sub": sub, "difference": "missing_excel"})
                    counts[(stage, "missing_excel")] += 1
                    continue
                a = normalize(row.get("acceptCond"))
                b = normalize(current.get("acceptCond"))
                left_comb = row.get("acceptCondComb", "LOGIC_NONE")
                right_comb = current.get("acceptCondComb", "LOGIC_NONE")
                classification = classify_accept(a, b, left_comb, right_comb)
                if classification:
                    counts[(stage, classification)] += 1
                    if classification != "no_compatibility_evidence":
                        item = {"stage": stage, "main": main_id, "sub": sub,
                                "classification": classification,
                                "binCompatConditions": a, "excelConditions": b,
                                "binComb": left_comb, "excelComb": right_comb}
                        results.append(item)
                for field in ("beginExec", "finishExec", "failExec"):
                    be = [x for x in row.get(field, []) if x.get("type")]
                    ex = [x for x in current.get(field, []) if x.get("type")]
                    if ex and be and be != ex:
                        counts[(stage, "action_conflict")] += 1
                        results.append({"stage": stage, "main": main_id, "sub": sub,
                                        "field": field, "binActions": be, "excelActions": ex})
    payload = {
        "scope": "Genshin 7.1 Mondstadt prelude / Acts I-III",
        "sourceLabels": {
            "bin": "historical compatibility, not 7.1 native acceptCond",
            "excel": "flattened Asta materialization (may be synthetic)",
        },
        "counts": {"%s:%s" % k: v for k, v in sorted(counts.items())},
        "differences": results,
    }
    path = Path("mondstadt-quest-drift.json")
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("SCOPED DRIFT counts:", json.dumps(payload["counts"], sort_keys=True))
    print("SCOPED DRIFT sample:", json.dumps(results[:12], ensure_ascii=False)[:12000])
    print("REPORT", path, "actionable differences", len(results), "(missing historical evidence counted separately)")


if __name__ == "__main__":
    main()
