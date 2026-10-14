#!/usr/bin/env python3
"""Collect source-pinned Genshin 7.1 weapon -> ascension-group observations.

This is an ExcelBin source-row map, not proof that the client can obtain or
upgrade every configured weapon. Do not fill absent material IDs from templates.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "versions/7.1.0-global/analyses/progression/weapon/7.1-weapon-promote-map.json"
SOURCE_REPO = "RinoPaw/AstaPS-Resource"
SOURCE_COMMIT = "b0f3a2791607cab2a4c24cb9ef249dd2d94d7ffd"
EXPECTED_BLOBS = {
    "WeaponExcelConfigData.json": "5679642944d34787a11567cb1e99ff4bde6d150e",
    "WeaponPromoteExcelConfigData.json": "cd259ca9516b07342af617ddc515c4676b3f5570",
}


def load_resources(directory: Path) -> tuple[dict[str, list[dict]], dict[str, dict]]:
    tables = {}
    evidence = {}
    for filename, expected in EXPECTED_BLOBS.items():
        raw = (directory / filename).read_bytes()
        actual = hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest()
        if actual != expected:
            raise ValueError(f"{filename}: Git blob SHA mismatch ({actual} != {expected})")
        rows = json.loads(raw)
        if not isinstance(rows, list):
            raise ValueError(f"{filename}: expected JSON array")
        tables[filename.removesuffix(".json")] = rows
        evidence[filename] = {"gitBlobSha": actual, "rowCount": len(rows)}
    return tables, evidence


def build_snapshot(tables: dict[str, list[dict]], evidence: dict[str, dict]) -> dict:
    weapons = tables["WeaponExcelConfigData"]
    promote_rows = tables["WeaponPromoteExcelConfigData"]
    by_group: dict[int, list[dict]] = defaultdict(list)
    for row in promote_rows:
        by_group[row["weaponPromoteId"]].append(row)

    if len({w["id"] for w in weapons}) != len(weapons):
        raise ValueError("duplicate weapon IDs")

    groups = []
    groups_with_missing_item_ids = []
    groups_without_material_counts = []
    shortened_groups = []
    missing_id_slots = 0
    for promote_id, rows in sorted(by_group.items()):
        stages = []
        has_missing_id = False
        has_material_count = False
        for row in sorted(rows, key=lambda r: r.get("promoteLevel") or 0):
            items = []
            for slot, item in enumerate(row.get("costItems", [])):
                item_id = item.get("id") or None
                count = item.get("count") or 0
                if not item_id and not count:
                    continue
                if not isinstance(count, int) or count < 0:
                    raise ValueError(f"{promote_id}: invalid item count at slot {slot}")
                if item_id is not None and (not isinstance(item_id, int) or item_id <= 0):
                    raise ValueError(f"{promote_id}: invalid item ID at slot {slot}")
                if count:
                    has_material_count = True
                if count and item_id is None:
                    has_missing_id = True
                    missing_id_slots += 1
                items.append({"slot": slot, "itemId": item_id, "count": count})

            stages.append({
                "promoteLevel": row.get("promoteLevel") or 0,
                "unlockMaxLevel": row["unlockMaxLevel"],
                "requiredPlayerLevel": row.get("requiredPlayerLevel") or None,
                "coinCost": row.get("coinCost") or 0,
                "costItems": items,
                "addProps": [
                    {"propType": prop["propType"], "value": prop["value"]}
                    for prop in row.get("addProps", [])
                    if prop.get("propType") and prop.get("value")
                ],
            })
        levels = [stage["promoteLevel"] for stage in stages]
        if levels not in (list(range(5)), list(range(7))):
            raise ValueError(f"{promote_id}: unexpected stages {levels}")
        if len(stages) == 5:
            shortened_groups.append(promote_id)
        if has_missing_id:
            groups_with_missing_item_ids.append(promote_id)
        if not has_material_count:
            groups_without_material_counts.append(promote_id)
        groups.append({"weaponPromoteId": promote_id, "stages": stages})

    weapon_rows = []
    for row in sorted(weapons, key=lambda w: w["id"]):
        promote_id = row["weaponPromoteId"]
        if promote_id not in by_group:
            raise ValueError(f"weapon {row['id']}: missing promote group {promote_id}")
        weapon_rows.append({
            "weaponId": row["id"],
            "rarity": row["rankLevel"],
            "weaponType": row["weaponType"],
            "iconName": row.get("icon") or None,
            "weaponPromoteId": promote_id,
            "weaponBaseExp": row.get("weaponBaseExp") or 0,
            "weaponProps": [
                {
                    "propType": prop.get("propType") or None,
                    "curveType": prop.get("type") or None,
                    "initialValue": prop.get("initValue") or 0,
                }
                for prop in row.get("weaponProp", [])
            ],
        })

    refs: dict[int, list[dict]] = defaultdict(list)
    for row in weapon_rows:
        refs[row["weaponPromoteId"]].append(row)
    unreferenced = sorted(set(by_group) - set(refs))
    shared = sorted(group_id for group_id, rows in refs.items() if len(rows) > 1)
    rarity_counts = {
        str(rank): sum(w["rarity"] == rank for w in weapon_rows)
        for rank in range(1, 6)
    }
    if (len(weapon_rows), len(promote_rows), len(groups), len(refs),
            unreferenced, len(shortened_groups), len(groups_with_missing_item_ids),
            missing_id_slots, groups_without_material_counts, rarity_counts) != (
            287, 1814, 262, 260, [14411, 14503], 10, 9, 162, [11521],
            {"1": 15, "2": 5, "3": 28, "4": 149, "5": 90}):
        raise ValueError("unexpected pinned weapon coverage or anomaly counts")

    return {
        "schemaVersion": 1,
        "target": "Genshin Impact 7.1.0 Global",
        "scope": (
            "source-row weapon/promote observations, including test and unused entries; "
            "no playability, native payment, or client-runtime claim"
        ),
        "source": {
            "repository": SOURCE_REPO,
            "commit": SOURCE_COMMIT,
            "basePath": "ExcelBinOutput",
            "files": evidence,
        },
        "summary": {
            "weaponCount": len(weapon_rows),
            "weaponCountByRarity": rarity_counts,
            "promoteGroupCount": len(groups),
            "referencedPromoteGroupCount": len(refs),
            "unreferencedPromoteGroupIds": unreferenced,
            "sharedPromoteGroupIds": shared,
            "shortenedPromoteGroupIds": shortened_groups,
            "missingMaterialIdGroupIds": groups_with_missing_item_ids,
            "missingMaterialIdSlots": missing_id_slots,
            "noMaterialCountGroupIds": groups_without_material_counts,
            "missingPromoteReferences": 0,
        },
        "weapons": weapon_rows,
        "promoteGroups": groups,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resources", type=Path, required=True,
                        help="directory of unchanged pinned ExcelBinOutput JSON files")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--check", action="store_true",
                        help="fail if the committed snapshot differs from pinned sources")
    args = parser.parse_args()
    tables, evidence = load_resources(args.resources)
    snapshot = build_snapshot(tables, evidence)
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != snapshot:
            raise SystemExit("weapon progression snapshot differs from pinned resources")
        print("PASS: pinned 7.1 weapon progression map matches")
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
