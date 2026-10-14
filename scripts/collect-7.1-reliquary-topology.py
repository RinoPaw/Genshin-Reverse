#!/usr/bin/env python3
"""Collect 7.1 Reliquary depot topology without importing restored probability weights.

All inputs must be unchanged blobs from the pinned AstaPS-Resource revision.
The resulting artifact describes config-row references, not drop/roll probabilities.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (ROOT / "versions/7.1.0-global/windows-x64/analyses/artifact-generation"
          / "7.1-reliquary-depot-topology.json")
SOURCE_REPO = "RinoPaw/AstaPS-Resource"
SOURCE_COMMIT = "b0f3a2791607cab2a4c24cb9ef249dd2d94d7ffd"
EXPECTED_BLOBS = {
    "ReliquaryExcelConfigData.json": "dc617e939a0ad4864f88e32dbf98ace9ac11649f",
    "ReliquaryMainPropExcelConfigData.json": "9b8a923064726f32afe37e927fc73bc712a36b14",
    "ReliquaryAffixExcelConfigData.json": "f4f8ce04a903b463c505a09fbbd24299ad06b4ec",
}


def load_resources(directory: Path) -> tuple[dict[str, list[dict]], dict[str, dict]]:
    tables = {}
    evidence = {}
    for filename, expected in EXPECTED_BLOBS.items():
        raw = (directory / filename).read_bytes()
        actual = hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest()
        if actual != expected:
            raise ValueError(f"{filename}: source blob {actual} != pinned {expected}")
        rows = json.loads(raw)
        if not isinstance(rows, list):
            raise ValueError(f"{filename}: expected JSON array")
        tables[filename.removesuffix(".json")] = rows
        evidence[filename] = {"gitBlobSha": actual, "rowCount": len(rows)}
    return tables, evidence


def build_snapshot(tables: dict[str, list[dict]], evidence: dict[str, dict]) -> dict:
    items = tables["ReliquaryExcelConfigData"]
    main = tables["ReliquaryMainPropExcelConfigData"]
    affix = tables["ReliquaryAffixExcelConfigData"]

    for name, rows in [("ReliquaryExcel", items),
                       ("ReliquaryMainPropExcel", main),
                       ("ReliquaryAffixExcel", affix)]:
        ids = [r["id"] for r in rows]
        if len(ids) != len(set(ids)):
            raise ValueError(f"{name}: duplicate row IDs")

    mains = sorted([{
        "rowId": r["id"],
        "mainPropDepotId": r["propDepotId"],
        "propType": r["propType"],
    } for r in main], key=lambda r: r["rowId"])
    affixes = sorted([{
        "rowId": r["id"],
        "appendPropDepotId": r["depotId"],
        "groupId": r.get("group_id", r.get("groupId")),
        "propType": r["propType"],
        "propValue": r["propValue"],
    } for r in affix], key=lambda r: r["rowId"])
    known_mains = {r["mainPropDepotId"] for r in mains}
    known_affixes = {r["appendPropDepotId"] for r in affixes}

    mapped_items = []
    for r in sorted(items, key=lambda item: item["id"]):
        main_depot = r["mainPropDepotId"]
        append_depot = r["appendPropDepotId"]
        if main_depot not in known_mains or append_depot not in known_affixes:
            raise ValueError(f"reliquary {r['id']}: missing referenced depot")
        mapped_items.append({
            "itemId": r["id"],
            "rarity": r["rankLevel"],
            "equipType": r["equipType"],
            "setId": r.get("setId"),
            "mainPropDepotId": main_depot,
            "appendPropDepotId": append_depot,
            "appendPropNum": r.get("appendPropNum"),
            "maxLevel": r["maxLevel"],
            "addPropLevels": r.get("addPropLevels"),
        })

    five_star = [r for r in mapped_items if r["rarity"] == 5]
    special = [r for r in five_star if r["appendPropDepotId"] != 501]
    by_rarity = Counter(r["rarity"] for r in mapped_items)
    by_depot = Counter(r["appendPropDepotId"] for r in five_star)
    special_slot_depots: dict[str, list[int]] = {}
    for r in special:
        special_slot_depots.setdefault(r["equipType"], []).append(r["appendPropDepotId"])

    if (len(mapped_items), len(mains), len(affixes), len(five_star),
            len(special), dict(sorted(by_rarity.items())),
            dict(sorted(by_depot.items()))) != (
            4352, 66, 350, 1614, 589,
            {1: 332, 2: 325, 3: 800, 4: 1281, 5: 1614},
            {501: 1025, 961: 102, 962: 102, 963: 127, 964: 128, 965: 130}):
        raise ValueError("unexpected pinned Reliquary source coverage")

    # Per-depot item lists do not imply that variants are ordinary drops.
    routes: dict[str, list[int]] = {}
    for r in five_star:
        routes.setdefault(str(r["appendPropDepotId"]), []).append(r["itemId"])

    return {
        "schemaVersion": 1,
        "target": "Genshin Impact 7.1.0 Global",
        "scope": (
            "7.1 integrated resource topology only; source weight and "
            "upgradeWeight intentionally excluded (historical restoration); "
            "no runtime selection or distribution claim"
        ),
        "source": {
            "repository": SOURCE_REPO,
            "commit": SOURCE_COMMIT,
            "basePath": "ExcelBinOutput",
            "files": evidence,
        },
        "summary": {
            "reliquaryItemCount": len(mapped_items),
            "itemCountByRarity": {str(k): v for k, v in sorted(by_rarity.items())},
            "mainPropRowCount": len(mains),
            "appendPropRollRowCount": len(affixes),
            "fiveStarItemCount": len(five_star),
            "fiveStarItemCountByAppendDepot": {
                str(k): v for k, v in sorted(by_depot.items())
            },
            "fiveStarNon501ItemCount": len(special),
            "fiveStarNon501DepotsBySlot": {
                key: sorted(set(value)) for key, value in sorted(special_slot_depots.items())
            },
            "unresolvedMainDepotReferences": 0,
            "unresolvedAppendDepotReferences": 0,
        },
        "fiveStarItemIdsByAppendDepot": dict(sorted(routes.items(), key=lambda kv: int(kv[0]))),
        "reliquaries": mapped_items,
        "mainProps": mains,
        "appendProps": affixes,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resources", type=Path, required=True,
                        help="unaltered ExcelBinOutput from the pinned Resource commit")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--check", action="store_true",
                        help="compare regenerated observations with the committed snapshot")
    args = parser.parse_args()
    tables, evidence = load_resources(args.resources)
    snapshot = build_snapshot(tables, evidence)
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != snapshot:
            raise SystemExit("reliquary depot topology differs from pinned resources")
        print("PASS: 7.1 Reliquary topology matches pinned rows")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n",
                               encoding="utf-8")
        print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
