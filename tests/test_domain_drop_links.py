"""Offline checks for Dungeon graph coverage and structural failure cases."""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from genshinre.dungeondrops import collect_dungeon_drop_links

FILE = (
    Path(__file__).resolve().parents[1]
    / "versions/7.1.0-global/analyses/progression/economy/7.1-domain-drop-links.json"
)


class DomainDropLinkTests(unittest.TestCase):
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
                "ExcelBinOutput/DailyDungeonConfigData.json":
                    "df450f5daeb484e94840af7e207f20cdde8cedbd",
            },
        )
        s = data["summary"]
        self.assertEqual(s["dungeonRows"], 373)
        for subtype, counts in {
            "DUNGEON_SUB_TALENT": (104, 56, 48, 0, 96),
            "DUNGEON_SUB_WEAPON": (104, 56, 48, 0, 96),
            "DUNGEON_SUB_RELIQUARY": (98, 54, 44, 0, 0),
            "DUNGEON_SUB_BOSS": (66, 0, 0, 66, 0),
            "UNCLASSIFIED": (1, 0, 0, 1, 0),
        }.items():
            summary = s["bySubType"][subtype]
            self.assertEqual(tuple(summary[k] for k in (
                "dungeonRows", "resolvedRootCount", "missingRootCount", "noPointerCount", "scheduleReferencedRows")), counts)
        self.assertEqual((s["reachableDropTableNodes"], s["reachableDropSubTableNodes"]), (414, 216))
        self.assertEqual(len(self.domains), 373)
        self.assertEqual(len(self.nodes), 630)
        self.assertEqual(s["unmatchedScheduleDungeonIds"], [])
        self.assertEqual(
            {d["cityId"] for d in self.domains.values()
             if d["subType"] == "DUNGEON_SUB_TALENT" and d["rootStatus"] == "ROOT_MISSING"},
            {5, 6, 7, 8},
        )

    def test_every_linked_root_and_nested_reference(self):
        for dungeon in self.domains.values():
            if dungeon["type"] == "DUNGEON_DAILY_FIGHT":
                self.assertEqual((dungeon["baseResinCostItemId"], dungeon["baseResinCostCount"]), (106, 20))
            if dungeon["rootStatus"] == "ROOT_PRESENT":
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
                self.assertEqual(entry["targetKind"] == "DROP_NODE", entry["itemId"] in self.nodes)
        self.assertIn("no runtime/probability assertion", self.data["scope"])

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
        self.assertEqual(self.domains[4434]["rootStatus"], "ROOT_MISSING")

    def test_schedule_references_preserve_row_identity(self):
        self.assertEqual(self.domains[4313]["scheduleReferences"], [
            {"dailyDungeonConfigId": 29, "weekdays": ["sunday"]},
            {"dailyDungeonConfigId": 32, "weekdays": ["monday", "thursday"]},
        ])
        self.assertEqual(self.domains[4303]["scheduleReferences"], [])
        self.assertEqual(self.domains[5116]["rootStatus"], "NO_POINTER")


class GraphStructureTests(unittest.TestCase):
    @staticmethod
    def node(node_id, child):
        return {"id": node_id, "randomType": 1, "dropLevel": 0, "nodeType": 1,
                "dropVec": [{"itemId": child, "countRange": "2.2", "weight": 10000}]}

    @staticmethod
    def dungeon(pointer=10):
        return {"id": 1, "type": "DUNGEON_DAILY_FIGHT", "IAOMJCLOIEL": pointer}

    def test_cycle_and_ambiguous_ids_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "cyclic"):
            collect_dungeon_drop_links([self.dungeon()], [self.node(10, 11), self.node(11, 10)], [], [])
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            collect_dungeon_drop_links([self.dungeon()], [self.node(10, 12)], [self.node(10, 13)], [])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            collect_dungeon_drop_links([self.dungeon()], [self.node(10, 12)] * 2, [], [])

    def test_missing_roots_are_separate_from_absent_pointers(self):
        a = self.dungeon(99)
        b = {**self.dungeon(None), "id": 2}
        result = collect_dungeon_drop_links([a, b], [], [], [])
        self.assertEqual([d["rootStatus"] for d in result["domains"]], ["ROOT_MISSING", "NO_POINTER"])

    def test_raw_decimal_and_unknown_terminal_are_preserved(self):
        result = collect_dungeon_drop_links([self.dungeon()], [self.node(10, 999)], [], [])
        entry = result["dropNodes"][0]["dropVec"][0]
        self.assertEqual(entry, {"itemId": 999, "countRange": "2.2", "weight": 10000, "targetKind": "TERMINAL_ID"})


if __name__ == "__main__":
    unittest.main()
