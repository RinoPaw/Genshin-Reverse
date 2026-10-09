"""Offline regression checks for the source-pinned 7.1 talent costs."""

import json
import unittest
from pathlib import Path


SNAPSHOT = (Path(__file__).resolve().parents[1] /
            "versions/7.1.0-global/analyses/progression/7.1-talent-cost-groups.json")


class TalentCostSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        cls.groups = {g["proudSkillGroupId"]: g for g in cls.data["proudSkillGroups"]}

    def test_provenance_and_coverage(self):
        data = self.data
        self.assertEqual(data["source"]["commit"], "b0f3a2791607cab2a4c24cb9ef249dd2d94d7ffd")
        self.assertEqual(data["schemaVersion"], 1)
        self.assertEqual(data["summary"]["skillDepotCount"], 169)
        self.assertEqual(data["summary"]["linkedProudSkillGroupCount"], 391)
        self.assertEqual(data["summary"]["fullLevel1To10Groups"], 389)
        self.assertEqual(data["summary"]["standardCostPatternGroups"], 385)
        self.assertEqual(data["summary"]["pyroTravelerCostPatternGroups"], 4)
        self.assertEqual(data["summary"]["level1OnlyGroupIds"], [233, 4133])
        self.assertEqual(len(self.groups), 391)
        self.assertEqual(len(data["skillDepots"]), 169)
        self.assertEqual(
            {k: v["rowCount"] for k, v in data["source"]["files"].items()},
            {
                "ProudSkillExcelConfigData.json": 6273,
                "AvatarSkillDepotExcelConfigData.json": 169,
                "AvatarSkillExcelConfigData.json": 1149,
            },
        )
        self.assertTrue(all(len(x["gitBlobSha"]) == 40 for x in data["source"]["files"].values()))

    def test_all_skill_depot_references(self):
        linked = set()
        for depot in self.data["skillDepots"]:
            for skill in [*depot["combatSkillSlots"], depot["energySkill"]]:
                if skill and skill["proudSkillGroupId"]:
                    self.assertIn(skill["proudSkillGroupId"], self.groups)
                    linked.add(skill["proudSkillGroupId"])
        self.assertEqual(linked, set(self.groups))
        for group in self.groups.values():
            levels = group["levels"]
            if group["proudSkillGroupId"] in (233, 4133):
                self.assertEqual([row["level"] for row in levels], [1])
            else:
                self.assertEqual([row["level"] for row in levels], list(range(1, 11)))
            self.assertTrue(all(x["coinCost"] >= 0 for x in levels))
            self.assertTrue(all(item["count"] > 0 for level in levels
                                for item in level["costItems"]))

    def test_jean_standard_costs(self):
        jean = self.groups[331]["levels"]
        self.assertEqual(jean[1]["coinCost"], 12500)
        self.assertEqual(
            [(x["itemId"], x["count"]) for x in jean[1]["costItems"]],
            [(104304, 3), (112005, 6)],
        )
        self.assertEqual(sum(x["coinCost"] for x in jean), 1_652_500)
        self.assertEqual(jean[-1]["proudSkillId"], 33110)
        self.assertEqual(
            [(x["itemId"], x["count"]) for x in jean[-1]["costItems"]],
            [(104306, 16), (112007, 12), (113003, 2), (104319, 1)],
        )
        self.assertEqual(sum(x["costItems"][2]["count"] for x in jean[6:]), 6)

    def test_pyro_traveler_exception(self):
        for group_id in (530, 531, 532, 539):
            with self.subTest(group_id=group_id):
                levels = self.groups[group_id]["levels"]
                self.assertEqual(sum(row["coinCost"] for row in levels), 1_652_500)
                self.assertEqual([row["costItems"][2]["count"] for row in levels[6:]],
                                 [1, 1, 1, 1])
                self.assertEqual(levels[-1]["costItems"][-1]["itemId"], 104319)
        self.assertEqual(
            [(x["itemId"], x["count"]) for x in self.groups[530]["levels"][-1]["costItems"]],
            [(104355, 16), (112106, 12), (113063, 1), (104319, 1)],
        )


if __name__ == "__main__":
    unittest.main()
