import json
from pathlib import Path
import unittest

from genshinre.reliquaryclaimaudit import positive_leaves

ECON = (Path(__file__).resolve().parents[1] /
        "versions/7.1.0-global/analyses/progression/economy")


class ReliquaryClaimAuditTests(unittest.TestCase):
    def test_source_graph_leaves(self):
        graph = json.loads((ECON / "7.1-domain-drop-links.json").read_text(encoding="utf-8"))
        nodes = {row["id"]: row for row in graph["dropNodes"]}
        self.assertIn(51311, positive_leaves(85112000, nodes))
        self.assertIn(20412, positive_leaves(85143500, nodes))
        with self.assertRaisesRegex(ValueError, "cycle"):
            positive_leaves(1, {1: {"dropVec": [{"weight": 1, "itemId": 2}]},
                                2: {"dropVec": [{"weight": 1, "itemId": 1}]}})

    def test_published_validation_edge(self):
        snapshot = json.loads(
            (ECON / "7.1-artifact-native-only-claim-audit.json").read_text(encoding="utf-8"))
        current = json.loads(
            (ECON / "7.1-current-asta-dungeon-reward-audit.json").read_text(encoding="utf-8"))
        rows = snapshot["dungeons"]
        self.assertEqual([r["dungeonId"] for r in rows],
                         [5000, 5001, 5002, 5008, 5050, 5100, 5101])
        ids = {r["dungeonId"] for r in current["dungeons"]
               if r["subType"] == "DUNGEON_SUB_RELIQUARY"
               and r["staticClaimRoute"] == "NATIVE_ONLY_CANDIDATE"}
        self.assertEqual(ids, {r["dungeonId"] for r in rows})
        for r in rows:
            self.assertEqual(r["previewArtifactSetIds"], r["nativeReliquarySetIds"])
            self.assertFalse(r["directReliquaryPreviewItemIds"])
            self.assertGreater(r["nativeReliquaryItemCount"], 0)
            self.assertTrue(r["rejectedProxyIssues"])
            self.assertEqual(r["predictedCurrentRewardSource"], "NONE")
        self.assertEqual(snapshot["summary"]["predictedRejectedBeforePayment"], 7)


if __name__ == "__main__":
    unittest.main()
