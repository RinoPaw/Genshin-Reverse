"""Pinned 7.1 avatar source-row material and primary skill mapping checks."""

from __future__ import annotations

import json
import unittest
from pathlib import Path


SNAPSHOT = (Path(__file__).resolve().parents[1] /
            "versions/7.1.0-global/analyses/progression/character/7.1-avatar-material-skill-map.json")


class AvatarGrowthSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        cls.avatars = {a["avatarId"]: a for a in cls.data["avatars"]}
        cls.groups = {g["avatarPromoteId"]: g for g in cls.data["ascensionGroups"]}

    def test_source_provenance(self):
        d = self.data
        self.assertEqual(d["source"]["commit"], "b0f3a2791607cab2a4c24cb9ef249dd2d94d7ffd")
        self.assertEqual(d["summary"]["avatarCount"], 167)
        self.assertEqual(d["summary"]["formallyMarkedAvatarCount"], 132)
        self.assertEqual(d["summary"]["ascensionGroupCount"], 125)
        self.assertEqual(d["summary"]["nonProudSkillReferences"], 39)
        self.assertEqual(len(self.avatars), len(d["avatars"]))
        self.assertEqual(len(self.groups), len(d["ascensionGroups"]))
        self.assertEqual(
            {name: info["rowCount"] for name, info in d["source"]["files"].items()},
            {
                "AvatarExcelConfigData.json": 167,
                "AvatarPromoteExcelConfigData.json": 875,
                "AvatarSkillDepotExcelConfigData.json": 169,
                "AvatarSkillExcelConfigData.json": 1149,
            },
        )
        self.assertTrue(all(len(x["gitBlobSha"]) == 40 for x in d["source"]["files"].values()))

    def test_references_and_all_ascension_stages(self):
        for a in self.data["avatars"]:
            with self.subTest(avatarId=a["avatarId"]):
                self.assertIn(a["avatarPromoteId"], self.groups)
                self.assertTrue(a["skillDepotId"] > 0)
                self.assertTrue(all(slot["skillId"] >= 0 for slot in a["combatSkillSlots"]))
        for g in self.data["ascensionGroups"]:
            with self.subTest(group=g["avatarPromoteId"]):
                stages = g["stages"]
                self.assertEqual([s["promoteLevel"] for s in stages], list(range(7)))
                self.assertEqual([s["unlockMaxLevel"] for s in stages],
                                 [20, 40, 50, 60, 70, 80, 90])
                self.assertEqual(stages[0]["scoinCost"], 0)
                for s in stages:
                    self.assertTrue(all(item["count"] > 0 and item["itemId"] > 0
                                        for item in s["costItems"]))

    def test_jean_source_link_and_material_totals(self):
        jean = self.avatars[10000003]
        self.assertEqual(jean["avatarPromoteId"], 3)
        self.assertEqual(jean["skillDepotId"], 301)
        self.assertEqual([s["proudSkillGroupId"] for s in jean["combatSkillSlots"][:2]], [331, 332])
        self.assertEqual(jean["energySkill"]["proudSkillGroupId"], 339)
        stages = self.groups[3]["stages"][1:]
        self.assertEqual(sum(x["scoinCost"] for x in stages), 420000)
        boss = sum(item["count"] for s in stages
                   for item in s["costItems"] if item["itemId"] == 113001)
        self.assertEqual(boss, 46)
        self.assertEqual(stages[0]["costItems"],
                         [{"slot": 0, "itemId": 104151, "count": 1},
                          {"slot": 2, "itemId": 100057, "count": 3},
                          {"slot": 3, "itemId": 112005, "count": 3}])

    def test_traveler_is_not_ordinary_ascension_template(self):
        traveler = self.avatars[10000005]
        self.assertEqual(traveler["avatarPromoteId"], 12)
        self.assertEqual(traveler["skillDepotId"], 501)
        stages = self.groups[12]["stages"][1:]
        self.assertEqual(sum(s["scoinCost"] for s in stages), 420000)
        self.assertFalse(any(113000 <= x["itemId"] < 114000
                             for s in stages for x in s["costItems"]))


if __name__ == "__main__":
    unittest.main()
