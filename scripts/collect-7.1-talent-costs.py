#!/usr/bin/env python3
"""Rebuild the source-pinned 7.1 talent cost map from ExcelBinOutput JSON."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "versions/7.1.0-global/analyses/progression/7.1-talent-cost-groups.json"
SOURCE_REPO = "RinoPaw/AstaPS-Resource"
SOURCE_COMMIT = "b0f3a2791607cab2a4c24cb9ef249dd2d94d7ffd"
BLOBS = {
    "ProudSkillExcelConfigData.json": "9a386ae8c115ee7a78a578b03cc1a862fa3162e7",
    "AvatarSkillDepotExcelConfigData.json": "caf32c71bb0646fef87327a9a3c218dd90dacb88",
    "AvatarSkillExcelConfigData.json": "4685663a23e02cc0f3ff5c17b561219b791aa5d8",
}


def load_resources(directory: Path) -> tuple[dict[str, list[dict]], dict[str, dict]]:
    data = {}
    evidence = {}
    for filename, expected in BLOBS.items():
        raw = (directory / filename).read_bytes()
        actual = hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest()
        if actual != expected:
            raise ValueError(f"{filename}: Git blob SHA mismatch ({actual})")
        rows = json.loads(raw)
        if not isinstance(rows, list):
            raise ValueError(f"{filename}: expected JSON array")
        data[filename.removesuffix(".json")] = rows
        evidence[filename] = {"gitBlobSha": actual, "rowCount": len(rows)}
    return data, evidence


def build_snapshot(data: dict[str, list[dict]], evidence: dict[str, dict]) -> dict:
    proud = data["ProudSkillExcelConfigData"]
    depots = data["AvatarSkillDepotExcelConfigData"]
    skills = data["AvatarSkillExcelConfigData"]
    by_skill = {s["id"]: s for s in skills}
    if len(by_skill) != len(skills) or len({d["id"] for d in depots}) != len(depots):
        raise ValueError("duplicate skill or depot IDs")

    by_group: dict[int, list[dict]] = {}
    for row in proud:
        by_group.setdefault(row["proudSkillGroupId"], []).append(row)

    def skill_ref(skill_id: int) -> dict:
        skill = by_skill[skill_id]  # fail if the resource reference is broken
        return {"skillId": skill_id,
                "proudSkillGroupId": skill.get("proudSkillGroupId") or None}

    depot_rows = []
    for depot in sorted(depots, key=lambda x: x["id"]):
        combat = [
            {"index": slot, **skill_ref(skill_id)}
            for slot, skill_id in enumerate(depot.get("skills", []))
            if skill_id
        ]
        depot_rows.append({
            "skillDepotId": depot["id"],
            "combatSkillSlots": combat,
            "energySkill": skill_ref(depot["energySkill"]) if depot.get("energySkill") else None,
        })
    group_ids = sorted({
        item["proudSkillGroupId"]
        for depot in depot_rows
        for item in [*depot["combatSkillSlots"], depot["energySkill"]]
        if item and item["proudSkillGroupId"]
    })

    def cost_items(items: list[dict]) -> list[dict]:
        return [
            {"slot": slot, "itemId": item["id"], "count": item["count"]}
            for slot, item in enumerate(items)
            if isinstance(item.get("id"), int)
            and isinstance(item.get("count"), int)
            and item["count"] > 0
        ]

    groups = []
    for group_id in group_ids:
        rows = by_group[group_id]  # fail if a depot references a missing group
        levels = [
            {
                "level": row["level"],
                "proudSkillId": row["proudSkillId"],
                "coinCost": row.get("coinCost") or 0,
                "costItems": cost_items(row.get("costItems", [])),
            }
            for row in sorted(rows, key=lambda x: x["level"])
            if 1 <= row["level"] <= 10
        ]
        if len({x["level"] for x in levels}) != len(levels):
            raise ValueError(f"duplicate talent level in group {group_id}")
        groups.append({
            "proudSkillGroupId": group_id,
            "proudSkillType": rows[0]["proudSkillType"],
            "configuredMaxLevel": max(row["level"] for row in rows),
            "levels": levels,
        })

    by_id = {g["proudSkillGroupId"]: g for g in groups}
    def signature(group: dict) -> tuple:
        return tuple((x["coinCost"], tuple(y["count"] for y in x["costItems"]))
                     for x in group["levels"] if x["level"] >= 2)

    standard_signature = signature(by_id[331])
    pyro_signature = signature(by_id[530])
    standard = [g for g in groups if len(g["levels"]) == 10
                and signature(g) == standard_signature]
    pyro = [g for g in groups if len(g["levels"]) == 10
            and signature(g) == pyro_signature]
    sparse = [g["proudSkillGroupId"] for g in groups if len(g["levels"]) != 10]
    if (len(depot_rows), len(groups), len(standard), len(pyro), sparse) != (
        169, 391, 385, 4, [233, 4133]
    ):
        raise ValueError("pinned talent group coverage or signatures have changed")

    return {
        "schemaVersion": 1,
        "target": "Genshin Impact 7.1.0 Global",
        "scope": "referenced ProudSkill costs from all skill depots, including alternate and unused depots; no release-status or runtime behavior claim",
        "source": {
            "repository": SOURCE_REPO,
            "commit": SOURCE_COMMIT,
            "basePath": "ExcelBinOutput",
            "files": evidence,
        },
        "summary": {
            "skillDepotCount": len(depot_rows),
            "linkedProudSkillGroupCount": len(groups),
            "fullLevel1To10Groups": len(standard) + len(pyro),
            "standardCostPatternGroups": len(standard),
            "pyroTravelerCostPatternGroups": len(pyro),
            "level1OnlyGroupIds": sparse,
            "missingSkillOrProudReferences": 0,
        },
        "skillDepots": depot_rows,
        "proudSkillGroups": groups,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resources", type=Path, required=True,
                        help="directory containing unchanged pinned ExcelBinOutput JSON files")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--check", action="store_true",
                        help="compare regenerated data against an existing JSON snapshot")
    args = parser.parse_args()
    tables, evidence = load_resources(args.resources)
    snapshot = build_snapshot(tables, evidence)
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != snapshot:
            raise SystemExit("talent costs snapshot differs from pinned sources")
        print("PASS: pinned 7.1 talent costs match")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n",
                               encoding="utf-8")
        print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
