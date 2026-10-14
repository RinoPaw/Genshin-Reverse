"""Offline checks for the pinned 7.1 weapon-to-promotion source map."""

from __future__ import annotations

import json
import runpy
import unittest
from pathlib import Path

SNAPSHOT = (Path(__file__).resolve().parents[1] /
            "versions/7.1.0-global/analyses/progression/weapon/7.1-weapon-promote-map.json")


class WeaponProgressionSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        cls.weapons = {x["weaponId"]: x for x in cls.data["weapons"]}
        cls.groups = {x["weaponPromoteId"]: x for x in cls.data["promoteGroups"]}

    def test_pinned_provenance_and_coverage(self):
        data = self.data
        summary = data["summary"]
        self.assertEqual(data["schemaVersion"], 1)
        self.assertEqual(data["source"]["commit"], "b0f3a2791607cab2a4c24cb9ef249dd2d94d7ffd")
        self.assertEqual({k: v["gitBlobSha"] for k, v in data["source"]["files"].items()}, {
            "WeaponExcelConfigData.json": "5679642944d34787a11567cb1e99ff4bde6d150e",
            "WeaponPromoteExcelConfigData.json": "cd259ca9516b07342af617ddc515c4676b3f5570",
        })
        self.assertEqual({k: v["rowCount"] for k, v in data["source"]["files"].items()}, {
            "WeaponExcelConfigData.json": 287, "WeaponPromoteExcelConfigData.json": 1814,
        })
        self.assertEqual(len(self.weapons), summary["weaponCount"])
        self.assertEqual(summary["weaponCount"], 287)
        self.assertEqual(summary["weaponCountByRarity"],
                         {"1": 15, "2": 5, "3": 28, "4": 149, "5": 90})
        self.assertEqual(len(self.groups), summary["promoteGroupCount"])
        self.assertEqual(summary["promoteGroupCount"], 262)
        self.assertEqual(summary["referencedPromoteGroupCount"], 260)
        self.assertEqual(summary["missingPromoteReferences"], 0)

    def test_all_weapon_references_and_stage_structure(self):
        referenced = set()
        for weapon in self.weapons.values():
            with self.subTest(weapon=weapon["weaponId"]):
                group = weapon["weaponPromoteId"]
                self.assertIn(group, self.groups)
                self.assertGreaterEqual(weapon["rarity"], 1)
                self.assertLessEqual(weapon["rarity"], 5)
                self.assertTrue(weapon["weaponType"].startswith("WEAPON_"))
                referenced.add(group)
        self.assertEqual(len(referenced), 260)
        self.assertEqual(sorted(set(self.groups) - referenced), [14411, 14503])
        self.assertEqual(self.data["summary"]["unreferencedPromoteGroupIds"], [14411, 14503])

        shortened = []
        for group_id, group in self.groups.items():
            stages = group["stages"]
            with self.subTest(group=group_id):
                levels = [stage["promoteLevel"] for stage in stages]
                self.assertIn(levels, [list(range(5)), list(range(7))])
                if len(levels) == 5:
                    shortened.append(group_id)
                self.assertEqual(stages[0]["unlockMaxLevel"], 20)
                self.assertEqual(stages[0]["coinCost"], 0)
                for stage in stages:
                    self.assertGreaterEqual(stage["coinCost"], 0)
                    self.assertEqual(len(stage["costItems"]),
                                     len({item["slot"] for item in stage["costItems"]}))
        self.assertEqual(sorted(shortened), self.data["summary"]["shortenedPromoteGroupIds"])

    def test_standard_ascension_costs_and_shared_group(self):
        for group_id, expected_coin in [(11301, 105_000), (11401, 150_000),
                                        (11501, 225_000)]:
            with self.subTest(group=group_id):
                stages = self.groups[group_id]["stages"]
                self.assertEqual([s["unlockMaxLevel"] for s in stages],
                                 [20, 40, 50, 60, 70, 80, 90])
                self.assertEqual(sum(s["coinCost"] for s in stages), expected_coin)
                self.assertTrue(all(item["itemId"] is not None
                                    for s in stages for item in s["costItems"]))

        self.assertEqual(self.weapons[11401]["weaponPromoteId"], 11401)
        self.assertEqual(self.weapons[11501]["weaponPromoteId"], 11501)
        self.assertEqual(self.weapons[11506]["weaponPromoteId"], 11101)
        self.assertEqual(self.weapons[11506]["rarity"], 5)
        self.assertEqual(self.data["summary"]["sharedPromoteGroupIds"], [11101])
        self.assertEqual(len(self.groups[11101]["stages"]), 5)

    def test_unresolved_material_ids_are_not_invented(self):
        missing_groups = set()
        missing_slots = 0
        for group in self.groups.values():
            for stage in group["stages"]:
                for item in stage["costItems"]:
                    self.assertGreater(item["count"], 0)
                    if item["itemId"] is None:
                        missing_groups.add(group["weaponPromoteId"])
                        missing_slots += 1
        summary = self.data["summary"]
        self.assertEqual(sorted(missing_groups), summary["missingMaterialIdGroupIds"])
        self.assertEqual(len(missing_groups), 9)
        self.assertEqual(missing_slots, summary["missingMaterialIdSlots"])
        self.assertEqual(missing_slots, 162)
        self.assertEqual(
            self.groups[11419]["stages"][1]["costItems"],
            [{"slot": 0, "itemId": None, "count": 3},
             {"slot": 1, "itemId": None, "count": 3},
             {"slot": 2, "itemId": None, "count": 2}],
        )
        self.assertEqual(summary["noMaterialCountGroupIds"], [11521])
        self.assertTrue(all(not s["costItems"] for s in self.groups[11521]["stages"]))
        self.assertTrue(all(s["coinCost"] == 0 for s in self.groups[11521]["stages"]))


    def test_collector_rebuilds_committed_observations(self):
        """Check Python collector parity without downloading external source data."""
        script = Path(__file__).resolve().parents[1] / "scripts/collect-7.1-weapon-growth.py"
        build_snapshot = runpy.run_path(str(script))["build_snapshot"]

        weapons = [{
            "id": w["weaponId"],
            "rankLevel": w["rarity"],
            "weaponType": w["weaponType"],
            "icon": w["iconName"],
            "weaponPromoteId": w["weaponPromoteId"],
            "weaponBaseExp": w["weaponBaseExp"],
            "weaponProp": [{
                "propType": prop["propType"],
                "type": prop["curveType"],
                "initValue": prop["initialValue"],
            } for prop in w["weaponProps"]],
        } for w in self.data["weapons"]]

        promotes = []
        for group in self.data["promoteGroups"]:
            for stage in group["stages"]:
                items = stage["costItems"]
                padded = [{} for _ in range(max((i["slot"] for i in items), default=-1) + 1)]
                for item in items:
                    padded[item["slot"]] = {
                        "id": item["itemId"],
                        "count": item["count"],
                    }
                promotes.append({
                    "weaponPromoteId": group["weaponPromoteId"],
                    "promoteLevel": stage["promoteLevel"],
                    "unlockMaxLevel": stage["unlockMaxLevel"],
                    "requiredPlayerLevel": stage["requiredPlayerLevel"],
                    "coinCost": stage["coinCost"],
                    "costItems": padded,
                    "addProps": stage["addProps"],
                })

        rebuilt = build_snapshot({
            "WeaponExcelConfigData": weapons,
            "WeaponPromoteExcelConfigData": promotes,
        }, self.data["source"]["files"])
        self.assertEqual(rebuilt, self.data)


if __name__ == "__main__":
    unittest.main()
