"""Source-pinned 7.1 Reliquary topology and RNG-evidence boundary checks."""

from __future__ import annotations

import json
import runpy
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = (ROOT / "versions/7.1.0-global/windows-x64/analyses"
            / "artifact-generation/7.1-reliquary-depot-topology.json")
COLLECTOR = ROOT / "scripts/collect-7.1-reliquary-topology.py"


class ReliquaryTopologyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        cls.items = {r["itemId"]: r for r in cls.data["reliquaries"]}
        cls.mains = {r["rowId"]: r for r in cls.data["mainProps"]}
        cls.affixes = {r["rowId"]: r for r in cls.data["appendProps"]}

    def test_provenance_and_complete_coverage(self):
        d = self.data
        self.assertEqual(d["schemaVersion"], 1)
        self.assertEqual(d["source"]["commit"], "b0f3a2791607cab2a4c24cb9ef249dd2d94d7ffd")
        self.assertEqual({k: v["gitBlobSha"] for k, v in d["source"]["files"].items()}, {
            "ReliquaryExcelConfigData.json": "dc617e939a0ad4864f88e32dbf98ace9ac11649f",
            "ReliquaryMainPropExcelConfigData.json": "9b8a923064726f32afe37e927fc73bc712a36b14",
            "ReliquaryAffixExcelConfigData.json": "f4f8ce04a903b463c505a09fbbd24299ad06b4ec",
        })
        self.assertEqual({k: v["rowCount"] for k, v in d["source"]["files"].items()}, {
            "ReliquaryExcelConfigData.json": 4352,
            "ReliquaryMainPropExcelConfigData.json": 66,
            "ReliquaryAffixExcelConfigData.json": 350,
        })
        self.assertEqual(len(self.items), 4352)
        self.assertEqual(len(self.mains), 66)
        self.assertEqual(len(self.affixes), 350)
        self.assertEqual(d["summary"]["itemCountByRarity"],
                         {"1": 332, "2": 325, "3": 800, "4": 1281, "5": 1614})

    def test_all_source_depot_links_are_resolved(self):
        main_depots = {r["mainPropDepotId"] for r in self.mains.values()}
        append_depots = {r["appendPropDepotId"] for r in self.affixes.values()}
        for item in self.items.values():
            with self.subTest(item_id=item["itemId"]):
                self.assertIn(item["mainPropDepotId"], main_depots)
                self.assertIn(item["appendPropDepotId"], append_depots)
                self.assertTrue(item["equipType"].startswith("EQUIP_"))
        self.assertEqual(self.data["summary"]["unresolvedMainDepotReferences"], 0)
        self.assertEqual(self.data["summary"]["unresolvedAppendDepotReferences"], 0)

    def test_five_star_special_depots_are_slot_specific(self):
        five = [r for r in self.items.values() if r["rarity"] == 5]
        actual = {str(k): v for k, v in sorted(
            Counter(r["appendPropDepotId"] for r in five).items())}
        self.assertEqual(len(five), 1614)
        self.assertEqual(actual, {
            "501": 1025, "961": 102, "962": 102,
            "963": 127, "964": 128, "965": 130,
        })
        self.assertEqual(self.data["summary"]["fiveStarItemCountByAppendDepot"], actual)
        self.assertEqual(self.data["summary"]["fiveStarNon501ItemCount"], 589)
        self.assertEqual(self.data["summary"]["fiveStarNon501DepotsBySlot"], {
            "EQUIP_BRACER": [962],
            "EQUIP_DRESS": [965],
            "EQUIP_NECKLACE": [961],
            "EQUIP_RING": [964],
            "EQUIP_SHOES": [963],
        })
        for depot, ids in self.data["fiveStarItemIdsByAppendDepot"].items():
            self.assertEqual(ids, [r["itemId"] for r in five
                                   if r["appendPropDepotId"] == int(depot)])

    def test_distinct_instances_do_not_imply_distribution(self):
        # Two config variants are not a fair coin just because there are two rows.
        a, b = self.items[20513], self.items[20514]
        self.assertEqual((a["rarity"], b["rarity"]), (5, 5))
        self.assertEqual(a["appendPropDepotId"], 501)
        self.assertEqual(a["mainPropDepotId"], b["mainPropDepotId"])
        self.assertEqual(a["appendPropNum"], 3)
        self.assertEqual(b["appendPropNum"], 4)
        self.assertEqual(a["addPropLevels"], [5, 9, 13, 17, 21])
        self.assertFalse(any("weight" in k.lower() for k in self.data["mainProps"][0]))
        self.assertFalse(any("weight" in k.lower() for k in self.data["appendProps"][0]))

    def test_collector_regenerates_from_observation_fields(self):
        """Exercise the production builder offline, including excluded RNG weights."""
        build = runpy.run_path(str(COLLECTOR))["build_snapshot"]
        items = [{
            "id": r["itemId"],
            "rankLevel": r["rarity"],
            "equipType": r["equipType"],
            "setId": r["setId"],
            "mainPropDepotId": r["mainPropDepotId"],
            "appendPropDepotId": r["appendPropDepotId"],
            "appendPropNum": r["appendPropNum"],
            "maxLevel": r["maxLevel"],
            "addPropLevels": r["addPropLevels"],
            "weight": 999,  # must never leak into a probability assertion
        } for r in self.data["reliquaries"]]
        mains = [{
            "id": r["rowId"], "propDepotId": r["mainPropDepotId"],
            "propType": r["propType"], "weight": 999,
        } for r in self.data["mainProps"]]
        affixes = [{
            "id": r["rowId"], "depotId": r["appendPropDepotId"],
            "group_id": r["groupId"], "propType": r["propType"],
            "propValue": r["propValue"], "weight": 999, "upgradeWeight": 999,
        } for r in self.data["appendProps"]]
        rebuilt = build({
            "ReliquaryExcelConfigData": items,
            "ReliquaryMainPropExcelConfigData": mains,
            "ReliquaryAffixExcelConfigData": affixes,
        }, self.data["source"]["files"])
        self.assertEqual(rebuilt, self.data)


if __name__ == "__main__":
    unittest.main()
