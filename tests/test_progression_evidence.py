"""Cheap, offline regression checks for pinned growth-table observations."""

import json
import unittest
from pathlib import Path


DATA_PATH = (Path(__file__).resolve().parents[1] /
             "versions/7.1.0-global/analyses/progression/7.1-resource-growth-observations.json")


class ProgressionEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snapshot = json.loads(DATA_PATH.read_text(encoding="utf-8"))
        cls.obs = cls.snapshot["observations"]

    def test_source_identity_and_large_blob_status(self):
        source = self.snapshot["source"]
        self.assertEqual(source["commit"], "b0f3a2791607cab2a4c24cb9ef249dd2d94d7ffd")
        self.assertEqual(len(source["files"]), 12)
        for name, info in source["files"].items():
            with self.subTest(name=name):
                self.assertEqual(len(info["git_blob_sha"]), 40)
                self.assertIn("populated", info["status"])
        for name in ("ProudSkill", "WeaponPromote", "Reliquary"):
            self.assertGreater(self.snapshot["source"]["files"][name + "ExcelConfigData.json"]["row_count"], 1000)

    def test_90_to_100_progression(self):
        rows = self.obs["character"]["post_90_source_rows"]
        self.assertEqual([(r["DEJBOJMHHJB"], r["BBPEGJLEEEC"], r["costItems"][0]["id"], r["costItems"][0]["count"]) for r in rows],
                         [(90, 95, 104300, 1), (95, 100, 104300, 2)])
        self.assertEqual(self.obs["character"]["post_90_material"]["material_type"], "MATERIAL_RARE_GROWTH_MATERIAL")
        self.assertEqual([r["level"] for r in self.obs["character"]["stat_curves_90_95_100"]], [90, 95, 100])

    def test_level_and_artifact_baselines(self):
        self.assertEqual(self.obs["character"]["ordinary_exp_1_to_90"], 8362650)
        self.assertEqual(self.obs["weapon"]["ordinary_exp_1_to_90_by_rarity"]["5"], 9064450)
        self.assertEqual(self.obs["artifact"]["five_star_exp_plus_0_to_20"], 270475)
        self.assertEqual([r["append_prop_num"] for r in self.obs["artifact"]["five_star_variant_examples"]], [3, 4])
        self.assertEqual(len(self.obs["world"]["world_level_source_rows"]), 9)
        self.assertEqual(self.obs["world"]["world_level_source_rows"][-1]["monsterLevel"], 100)
        self.assertEqual(len(self.obs["friendship"]["source_rows"]), 10)
        self.assertEqual(len(self.obs["account"]["ar_to_world_level_unlocks"]), 9)

    def test_talent_and_promotion_examples(self):
        rows = self.obs["talent"]["paid_levels_2_to_10"]
        self.assertEqual([r["level"] for r in rows], list(range(2, 11)))
        self.assertEqual(sum(r["coin_cost"] for r in rows), 1652500)
        groups = self.obs["weapon"]["promotion_group_examples"]
        self.assertEqual([sum(groups[g]["stage_coin_costs"]) for g in ("11301", "11401", "11501")],
                         [105000, 150000, 225000])


if __name__ == "__main__":
    unittest.main()
