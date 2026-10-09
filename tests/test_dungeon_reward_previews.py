"""Offline regression checks for pinned 7.1 Dungeon reward previews."""

import json
import unittest
from pathlib import Path


FILE = (Path(__file__).resolve().parents[1] /
        "versions/7.1.0-global/analyses/progression/economy/7.1-dungeon-reward-previews.json")


class DungeonRewardPreviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(FILE.read_text(encoding="utf-8"))
        cls.rows = cls.data["dungeons"]
        cls.by_id = {row["dungeonId"]: row for row in cls.rows}

    def test_source_identity_and_row_count(self):
        self.assertEqual(self.data["source"]["commit"],
                         "b0f3a2791607cab2a4c24cb9ef249dd2d94d7ffd")
        self.assertEqual(
            {k: v["rowCount"] for k, v in self.data["source"]["files"].items()},
            {"DungeonExcelConfigData.json": 2377,
             "RewardPreviewExcelConfigData.json": 1589},
        )
        summary = self.data["summary"]
        self.assertEqual(summary["dailyFightRows"], 307)
        self.assertEqual(summary["bossRows"], 66)
        self.assertEqual(summary["linkedPreviewRows"], 372)
        self.assertEqual(summary["noPreviewDungeonIds"], [5116])
        self.assertEqual(summary["dailyFightSubtypes"],
                         {"DUNGEON_SUB_RELIQUARY": 98,
                          "DUNGEON_SUB_TALENT": 104,
                          "DUNGEON_SUB_WEAPON": 104,
                          "null": 1})
        self.assertEqual(len(self.by_id), 373)

    def test_source_cost_and_preview_ownership(self):
        daily = [r for r in self.rows if r["type"] == "DUNGEON_DAILY_FIGHT"]
        self.assertEqual(len(daily), 307)
        self.assertTrue(all((r["resourceCostItemId"], r["resourceCostCount"]) ==
                            (106, 20) for r in daily))
        for r in self.rows:
            if r["dungeonId"] == 5116:
                self.assertIsNone(r["passRewardPreviewId"])
                self.assertEqual(r["previewItems"], [])
            else:
                self.assertIsNotNone(r["passRewardPreviewId"])
                self.assertTrue(r["previewItems"])
            self.assertTrue(all(item["itemId"] > 0 for item in r["previewItems"]))

    def test_specific_7_1_talent_preview(self):
        r = self.by_id[4200]
        self.assertEqual((r["type"], r["subType"]),
                         ("DUNGEON_DAILY_FIGHT", "DUNGEON_SUB_TALENT"))
        self.assertEqual((r["sceneId"], r["showLevel"], r["limitLevel"]),
                         (40200, 38, 25))
        self.assertEqual(r["passRewardPreviewId"], 20200)
        self.assertEqual(
            [(x["itemId"], x["displayCount"]) for x in r["previewItems"][:3]],
            [(102, "100"), (202, "1575"), (105, "15")],
        )
        self.assertEqual(
            {x["itemId"] for x in r["previewItems"] if x["itemId"] in (104301, 104304, 104307)},
            {104301, 104304, 104307},
        )

    def test_boss_preview_does_not_imply_drop_rates(self):
        r = self.by_id[103]
        self.assertEqual(r["type"], "DUNGEON_BOSS")
        self.assertEqual(r["passRewardPreviewId"], 15011)
        self.assertIsNone(r["resourceCostItemId"])
        self.assertIn(113021, [i["itemId"] for i in r["previewItems"]])
        self.assertIn("preview only", self.data["scope"])


if __name__ == "__main__":
    unittest.main()
