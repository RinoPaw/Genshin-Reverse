"""Offline regression checks for the pinned 7.1 3/4-substat DropTable branches."""

from __future__ import annotations

import json
import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/audit-7.1-reliquary-drop-variants.py"
REPORT = (ROOT / "versions/7.1.0-global/windows-x64/analyses"
          / "artifact-generation/7.1-reliquary-drop-variant-weights.json")


class ReliquaryDropVariantsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(REPORT.read_text(encoding="utf-8"))
        cls.module = runpy.run_path(str(SCRIPT))

    def test_pinned_sources_and_scope(self):
        src = self.data["source"]
        self.assertEqual(src["resourceCommit"],
                         "b0f3a2791607cab2a4c24cb9ef249dd2d94d7ffd")
        self.assertEqual(src["inputGitBlobs"], self.module["SNAPSHOT_BLOBS"])
        self.assertEqual(src["resourceGitBlobs"], self.module["RESOURCE_BLOBS"])
        self.assertIn("no proof", self.data["scope"])
        self.assertTrue(
            self.data["summary"]["requiresRandomTypeSemanticsToCallProbability"]
        )

    def test_all_configured_three_four_splits(self):
        s = self.data["summary"]
        self.assertEqual(s["artifactDungeonRows"], 98)
        self.assertEqual(s["resolvedRootCount"], 54)
        self.assertEqual(s["missingRootCount"], 44)
        self.assertEqual(s["configuredThreeFourBranchNodeCount"], 27)
        self.assertEqual(s["resolvedDomainsWithThreeFourBranch"], 27)
        self.assertEqual(s["resolvedDomainsWithoutThreeFourBranch"], 27)
        self.assertEqual(s["resolvedDomainRarityFamilies"],
                         {"1/2/3": 1, "2/3": 5, "3/4": 21, "3/4/5": 27})

        ids = set()
        for row in self.data["variantBranches"]:
            with self.subTest(node=row["nodeId"]):
                self.assertNotIn(row["nodeId"], ids)
                ids.add(row["nodeId"])
                self.assertEqual(row["randomType"], 0)
                self.assertEqual([b["initialSubstatCount"] for b in row["branches"]],
                                 [3, 4])
                self.assertEqual([b["configuredWeight"] for b in row["branches"]],
                                 [8000, 2000])
                self.assertEqual([len(b["itemIds"]) for b in row["branches"]],
                                 [10, 10])
                self.assertEqual(len(row["reachableDungeonIds"]), 1)
        self.assertEqual(len(ids), 27)

    def test_exact_example(self):
        row = next(x for x in self.data["variantBranches"] if x["nodeId"] == 85144515)
        self.assertEqual([b["childNodeId"] for b in row["branches"]],
                         [542523, 542524])
        self.assertEqual(row["branches"][0]["itemIds"][:5],
                         [20513, 20523, 20533, 20543, 20553])
        self.assertEqual(row["branches"][1]["itemIds"][:5],
                         [20514, 20524, 20534, 20544, 20554])
        self.assertEqual(row["reachableDungeonIds"], [5052])

    def test_fail_closed_when_weight_model_is_not_a_three_four_split(self):
        classify = self.module["classify_initial_affix_branch"]
        nodes = {
            1: {"id": 1, "dropVec": [{"targetKind": "TERMINAL_ID", "itemId": 11}]},
            2: {"id": 2, "dropVec": [{"targetKind": "TERMINAL_ID", "itemId": 12}]},
        }
        items = {
            11: {"appendPropNum": 3, "rarity": 5, "appendPropDepotId": 501},
            12: {"appendPropNum": 4, "rarity": 5, "appendPropDepotId": 501},
        }
        node = {
            "id": 3, "randomType": 0,
            "dropVec": [
                {"targetKind": "DROP_NODE", "itemId": 1, "weight": 8000},
                {"targetKind": "DROP_NODE", "itemId": 2, "weight": 2000},
            ],
        }
        self.assertIsNotNone(classify(node, nodes, items, {}))
        items[12]["rarity"] = 4
        self.assertIsNone(classify(node, nodes, items, {}))
        items[12]["rarity"] = 5
        node["randomType"] = 1
        self.assertIsNone(classify(node, nodes, items, {}))

    def test_exact_regeneration_from_two_committed_inputs(self):
        load = self.module["load_snapshot"]
        blobs = self.module["SNAPSHOT_BLOBS"]
        drop = load(self.module["DROP_INPUT"], blobs["dropGraph"])
        relic = load(self.module["RELIC_INPUT"], blobs["reliquaryTopology"])
        self.assertEqual(self.module["build_snapshot"](drop, relic), self.data)


if __name__ == "__main__":
    unittest.main()
