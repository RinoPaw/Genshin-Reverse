"""Offline regression checks for the source-bound 7.1 talent-domain drop-node graph."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

FILE = (
    Path(__file__).resolve().parents[1]
    / "versions/7.1.0-global/analyses/progression/economy/7.1-talent-domain-drop-links.json"
)


class TalentDomainDropLinkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(FILE.read_text(encoding="utf-8"))
        cls.domains = {d["dungeonId"]: d for d in cls.data["domains"]}
        cls.nodes = {n["id"]: n for n in cls.data["dropNodes"]}

    def test_source_and_coverage(self):
        data = self.data
        self.assertEqual(
            data["source"]["commit"],
            "b0f3a2791607cab2a4c24cb9ef249dd2d94d7ffd",
        )
        self.assertEqual(
            {k: v["gitBlobSha"] for k, v in data["source"]["files"].items()},
            {
                "ExcelBinOutput/DungeonExcelConfigData.json":
                    "92983c5d9d46bccf486b803b7cf65f2cdf9088cb",
                "Server/DropTableExcelConfigData.json":
                    "b46d383b535babd1be6b95e3ea031eef64d1fdfd",
                "Server/DropSubTableExcelConfigData.json":
                    "9397fb0b15c8c4cc82194ec429682f2ef4333767",
                "ExcelBinOutput/DungeonEntryExcelConfigData.json":
                    "e7a92f6df718148fad4dee47a691700407b1ddcf",
                "ExcelBinOutput/RewardPreviewExcelConfigData.json":
                    "a72b299e29c19007c48ed78b2e11aa33e274f98c",
            },
        )
        s = data["summary"]
        self.assertEqual(
            (s["talentDungeonRows"], s["resolvedRootCount"],
             s["missingRootCount"], s["reachableDropTableNodes"],
             s["reachableDropSubTableNodes"]),
            (104, 56, 48, 112, 6),
        )
        self.assertEqual(len(self.domains), 104)
        self.assertEqual(len(self.nodes), 118)
        self.assertEqual(
            {d["cityId"] for d in self.domains.values()
             if not d["rootPresent"]},
            {5, 6, 7, 8},
        )

    def test_every_linked_root_and_nested_reference(self):
        for dungeon in self.domains.values():
            self.assertEqual(
                (dungeon["baseResinCostItemId"], dungeon["baseResinCostCount"]),
                (106, 20),
            )
            if dungeon["rootPresent"]:
                self.assertIn(dungeon["rootDropId"], self.nodes)
                self.assertEqual(
                    self.nodes[dungeon["rootDropId"]]["table"],
                    "DropTableExcelConfigData",
                )
            else:
                self.assertNotIn(dungeon["rootDropId"], self.nodes)
        for node in self.nodes.values():
            for entry in node["dropVec"]:
                self.assertGreater(entry["itemId"], 0)
                self.assertGreaterEqual(entry["weight"], 0)
                self.assertIsInstance(entry["countRange"], str)
        self.assertIn("no runtime/probability assertion", self.data["scope"])

    def test_material_family_entry_join_is_unique(self):
        entries = self.data["entries"]
        self.assertEqual([e["entryExcelId"] for e in entries],
                         [10, 11, 15, 19, 24, 29, 33, 38])
        self.assertEqual([len(e["dungeonIds"]) for e in entries],
                         [16, 16, 12, 12, 12, 12, 12, 12])
        self.assertEqual(sorted(n for e in entries for n in e["dungeonIds"]),
                         sorted(self.domains))
        self.assertEqual(self.data["summary"]["talentEntryRows"], 8)
        for entry in entries:
            eligible = set(x for day in entry["materialCycleIds"] for x in day)
            for dungeon_id in entry["dungeonIds"]:
                r = self.domains[dungeon_id]
                with self.subTest(dungeonId=dungeon_id):
                    self.assertEqual(r["entryExcelId"], entry["entryExcelId"])
                    self.assertTrue(eligible.intersection(r["previewTalentMaterialIds"]))
        self.assertEqual(self.domains[4200]["entryExcelId"], 10)
        self.assertEqual(self.domains[4460]["entryExcelId"], 24)

    def test_sunday_domain_nested_subtable(self):
        self.assertEqual(self.domains[4200]["rootDropId"], 82012700)
        root = self.nodes[82012700]
        self.assertEqual(root["sourceType"], 27)
        self.assertEqual(root["randomType"], 1)
        self.assertIn(510000, [x["itemId"] for x in root["dropVec"]])
        self.assertIn(82012711, [x["itemId"] for x in root["dropVec"]])
        self.assertEqual(self.nodes[510000]["table"], "DropSubTableExcelConfigData")
        self.assertEqual(
            [x["itemId"] for x in self.nodes[510000]["dropVec"]],
            [104301, 104304, 104307],
        )
        self.assertFalse(self.domains[4434]["rootPresent"])


if __name__ == "__main__":
    unittest.main()
