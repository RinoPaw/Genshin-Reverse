#!/usr/bin/env python3
"""Read-only 7.1 resource comparison. Never applies or commits quest repairs.

Usage: python tools/audit_rino_resource_delta.py CURRENT_DIR RINO_DIR
Each directory contains ExcelBinOutput/QuestExcelConfigData.json, and may
contain ExcelBinOutput/MaterialExcelConfigData.json.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

INTERESTING = (
    "acceptCond", "acceptCondComb", "beginExec", "finishExec",
    "failExec", "finishCond", "finishCondComb", "failCond",
    "failCondComb", "gainItems",
)
MISSING = object()


def load_rows(path: Path) -> tuple[dict[int, dict], str]:
    raw = path.read_bytes()
    rows = json.loads(raw)
    if not isinstance(rows, list):
        raise ValueError(f"{path}: expected array")
    out: dict[int, dict] = {}
    for row in rows:
        if not isinstance(row, dict) or "subId" not in row:
            raise ValueError(f"{path}: invalid subquest record")
        sub_id = int(row["subId"])
        if sub_id in out:
            raise ValueError(f"{path}: duplicate subId {sub_id}")
        out[sub_id] = row
    return out, hashlib.sha256(raw).hexdigest()


def meaningful(v: object) -> bool:
    return v is not MISSING and v not in (None, "", [], {}, "LOGIC_NONE")


def audit_quests(current_dir: Path, old_dir: Path) -> None:
    rel = Path("ExcelBinOutput/QuestExcelConfigData.json")
    current, current_digest = load_rows(current_dir / rel)
    old, old_digest = load_rows(old_dir / rel)
    only_current = sorted(set(current) - set(old))
    only_old = sorted(set(old) - set(current))
    both = sorted(set(current) & set(old))
    field_counts = Counter()
    by_field = defaultdict(list)
    changes_by_kind = Counter()
    samples = defaultdict(list)
    touched = set()

    for sub_id in both:
        current_row, old_row = current[sub_id], old[sub_id]
        for field in sorted(set(current_row) | set(old_row)):
            a, b = current_row.get(field, MISSING), old_row.get(field, MISSING)
            if a == b:
                continue
            touched.add(sub_id)
            field_counts[field] += 1
            if len(by_field[field]) < 40:
                by_field[field].append(sub_id)
            kind = ("upstream_only" if meaningful(a) and not meaningful(b)
                    else "rino_only" if meaningful(b) and not meaningful(a)
                    else "different")
            changes_by_kind[kind] += 1
            if len(samples[(field, kind)]) < 12:
                samples[(field, kind)].append({
                    "subId": sub_id,
                    "upstream": None if a is MISSING else a,
                    "rino": None if b is MISSING else b,
                })

    print("QUESTEXCEL_SHA256", json.dumps({
        "upstream_main": current_digest, "play_rino": old_digest,
    }, sort_keys=True))
    print("QUESTEXCEL_POPULATION", json.dumps({
        "upstream_main": len(current), "play_rino": len(old),
        "only_upstream_ids": only_current[:100],
        "only_rino_ids": only_old[:100], "changed_existing_rows": len(touched),
    }, sort_keys=True))
    print("QUESTEXCEL_FIELD_COUNTS", json.dumps(dict(field_counts.most_common()), sort_keys=True))
    print("QUESTEXCEL_CHANGE_CLASSES", json.dumps(dict(changes_by_kind), sort_keys=True))
    for field in INTERESTING:
        print("QUEST_FIELD", field, json.dumps({
            "changed_count": field_counts[field],
            "first_40_sub_ids": by_field[field],
            "upstream_only_samples": samples[(field, "upstream_only")],
            "rino_only_samples": samples[(field, "rino_only")],
            "different_samples": samples[(field, "different")],
        }, ensure_ascii=False, separators=(",", ":")))

    for sub_id in both:
        a, b = current[sub_id], old[sub_id]
        if a.get("acceptCondComb") == b.get("acceptCondComb"):
            continue
        print("QUEST_COMBINER_DETAIL", sub_id, json.dumps({
            "mainId": a.get("mainId"),
            "upstream_comb": a.get("acceptCondComb"),
            "rino_comb": b.get("acceptCondComb"),
            "upstream_conditions": a.get("acceptCond"),
            "rino_conditions": b.get("acceptCond"),
        }, ensure_ascii=False, separators=(",", ":")))

    for sub_id in (35301, 35402, 35901, 39403):
        a, b = current.get(sub_id, {}), old.get(sub_id, {})
        for field in ("beginExec", "finishExec", "gainItems"):
            print("QUEST_GUARD", sub_id, field, json.dumps({
                "upstream": a.get(field, None),
                "play_rino": b.get(field, None),
            }, ensure_ascii=False, separators=(",", ":")))

    if not current or not old:
        raise ValueError("QuestExcel unexpectedly empty")


def audit_materials(current_dir: Path, old_dir: Path) -> None:
    rel = Path("ExcelBinOutput/MaterialExcelConfigData.json")
    for name, directory in (("upstream_main", current_dir), ("play_rino", old_dir)):
        path = directory / rel
        if not path.exists():
            print("MATERIAL_AUDIT", name, "unavailable")
            continue
        records = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(records, list):
            raise ValueError(f"{path}: expected array")
        avatar = []
        for rec in records:
            if not isinstance(rec, dict) or rec.get("materialType") != "MATERIAL_AVATAR":
                continue
            if any(isinstance(act, dict) and act.get("useOp") == "ITEM_USE_GAIN_AVATAR"
                   for act in rec.get("itemUse", [])):
                avatar.append((rec.get("id"), rec.get("useOnGain")))
        pending = [ident for ident, enabled in avatar if enabled is not True]
        print("MATERIAL_AUDIT", name, json.dumps({
            "avatar_gain_materials": len(avatar),
            "useOnGain_false_or_missing": len(pending),
            "sample_ids": pending[:40],
        }))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("upstream", type=Path)
    parser.add_argument("play_rino", type=Path)
    args = parser.parse_args()
    audit_quests(args.upstream, args.play_rino)
    audit_materials(args.upstream, args.play_rino)


if __name__ == "__main__":
    main()
