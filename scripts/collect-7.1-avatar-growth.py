#!/usr/bin/env python3
"""Rebuild the pinned 7.1 avatar ascension / primary skill-depot observation map.

Inputs are the four unmodified ExcelBinOutput JSON files from the source commit.
The Git blob SHAs are verified before a snapshot can be written.
This tool does not decide whether a row is released/playable or how skill-depot
switching and combat progression are enforced by the client.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "versions/7.1.0-global/analyses/progression/7.1-avatar-material-skill-map.json"
SOURCE_REPO = "RinoPaw/AstaPS-Resource"
SOURCE_COMMIT = "b0f3a2791607cab2a4c24cb9ef249dd2d94d7ffd"
EXPECTED_BLOBS = {
    "AvatarExcelConfigData.json": "f5072ba66596f5e18d09631765bc041697386899",
    "AvatarPromoteExcelConfigData.json": "e329398f7c5da38148e74d43f04f6acc68a30d8d",
    "AvatarSkillDepotExcelConfigData.json": "caf32c71bb0646fef87327a9a3c218dd90dacb88",
    "AvatarSkillExcelConfigData.json": "4685663a23e02cc0f3ff5c17b561219b791aa5d8",
}


def load_resources(root: Path) -> tuple[dict[str, list[dict]], dict[str, dict]]:
    tables = {}
    evidence = {}
    for filename, expected in EXPECTED_BLOBS.items():
        raw = (root / filename).read_bytes()
        actual = hashlib.sha1(f"blob {len(raw)}\\0".encode("ascii") + raw).hexdigest()
        if actual != expected:
            raise ValueError(f"{filename}: git blob {actual} != pinned {expected}")
        rows = json.loads(raw)
        if not isinstance(rows, list):
            raise ValueError(f"{filename}: expected a JSON array")
        tables[filename.removesuffix(".json")] = rows
        evidence[filename] = {"gitBlobSha": actual, "rowCount": len(rows)}
    return tables, evidence


def build_snapshot(tables: dict[str, list[dict]], evidence: dict[str, dict]) -> dict:
    avatars = tables["AvatarExcelConfigData"]
    promotes = tables["AvatarPromoteExcelConfigData"]
    depots = tables["AvatarSkillDepotExcelConfigData"]
    skills = tables["AvatarSkillExcelConfigData"]

    promote_by_id: dict[int, list[dict]] = {}
    for row in promotes:
        promote_by_id.setdefault(row["avatarPromoteId"], []).append(row)
    depot_by_id = {row["id"]: row for row in depots}
    skill_by_id = {row["id"]: row for row in skills}
    if len(depot_by_id) != len(depots) or len(skill_by_id) != len(skills):
        raise ValueError("duplicate skill-depot or skill ID")

    def skill_ref(skill_id: int | None) -> dict | None:
        if not skill_id:
            return None
        row = skill_by_id[skill_id]
        return {
            "skillId": skill_id,
            "proudSkillGroupId": row.get("proudSkillGroupId") or None,
            "abilityName": row.get("abilityName") or None,
        }

    avatar_rows = []
    for row in sorted(avatars, key=lambda x: x["id"]):
        depot_id = row["skillDepotId"]
        promote_id = row["avatarPromoteId"]
        depot = depot_by_id[depot_id]
        if promote_id not in promote_by_id:
            raise ValueError(f"missing promote group {promote_id}")
        combat_slots = []
        for index, skill_id in enumerate(depot.get("skills", [])):
            combat_slots.append({
                "index": index,
                **(skill_ref(skill_id) if skill_id else {
                    "skillId": 0,
                    "proudSkillGroupId": None,
                    "abilityName": None,
                }),
            })
        avatar_rows.append({
            "avatarId": row["id"],
            "iconName": row.get("iconName") or None,
            "useType": row.get("useType") or None,
            "avatarIdentityType": row.get("avatarIdentityType") or None,
            "qualityType": row.get("qualityType") or None,
            "weaponType": row.get("weaponType") or None,
            "avatarPromoteId": promote_id,
            "skillDepotId": depot_id,
            "combatSkillSlots": combat_slots,
            "energySkill": skill_ref(depot.get("energySkill")),
        })

    promote_groups = []
    for promote_id, rows in sorted(promote_by_id.items()):
        stages = []
        for row in sorted(rows, key=lambda x: x.get("promoteLevel") or 0):
            cost_items = [
                {"slot": slot, "itemId": item["id"], "count": item["count"]}
                for slot, item in enumerate(row.get("costItems", []))
                if isinstance(item.get("id"), int)
                and isinstance(item.get("count"), int)
                and item["count"] > 0
            ]
            props = [
                {"propType": prop["propType"], "value": prop.get("value") or 0}
                for prop in row.get("addProps", [])
                if prop.get("propType")
            ]
            stages.append({
                "promoteLevel": row.get("promoteLevel") or 0,
                "unlockMaxLevel": row.get("unlockMaxLevel") or None,
                "requiredPlayerLevel": row.get("requiredPlayerLevel") or None,
                "scoinCost": row.get("scoinCost") or 0,
                "costItems": cost_items,
                "addProps": props,
            })
        if [s["promoteLevel"] for s in stages] != list(range(7)):
            raise ValueError(f"{promote_id}: expected promote stages 0..6")
        promote_groups.append({"avatarPromoteId": promote_id, "stages": stages})

    if len(avatar_rows) != 167 or len(promote_groups) != 125:
        raise ValueError("unexpected pinned resource row counts")
    missing_proud = sum(
        1 for avatar in avatar_rows
        for skill in [*avatar["combatSkillSlots"], avatar["energySkill"]]
        if skill and skill["skillId"] > 0 and skill["proudSkillGroupId"] is None
    )
    return {
        "schemaVersion": 1,
        "target": "Genshin Impact 7.1.0 Global",
        "scope": "resource-row observations; primary skill depot only; no client-runtime/probability claim",
        "source": {
            "repository": SOURCE_REPO,
            "commit": SOURCE_COMMIT,
            "basePath": "ExcelBinOutput",
            "files": evidence,
        },
        "summary": {
            "avatarCount": len(avatar_rows),
            "formallyMarkedAvatarCount": sum(a["useType"] == "AVATAR_FORMAL" for a in avatar_rows),
            "ascensionGroupCount": len(promote_groups),
            "missingPrimaryReferences": 0,
            "nonProudSkillReferences": missing_proud,
        },
        "avatars": avatar_rows,
        "ascensionGroups": promote_groups,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resources", type=Path, required=True,
                        help="directory of pinned ExcelBinOutput JSON files")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--check", action="store_true",
                        help="verify committed JSON matches regenerated data without writing")
    args = parser.parse_args()
    tables, evidence = load_resources(args.resources)
    snapshot = build_snapshot(tables, evidence)
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != snapshot:
            raise SystemExit("progression snapshot differs from pinned resources")
        print(f"PASS: {len(snapshot['avatars'])} avatars, {len(snapshot['ascensionGroups'])} groups")
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
