import json
from pathlib import Path
import unittest

from genshinre.currentdungeonaudit import audit, pool_issues, SERVER_FILES

PATH = (Path(__file__).resolve().parents[1] /
        "versions/7.1.0-global/analyses/progression/economy/7.1-current-asta-dungeon-reward-audit.json")


class CurrentDungeonAuditTests(unittest.TestCase):
    def test_proxy_validation(self):
        self.assertEqual(pool_issues([{"counts": [2], "items": []}], "DUNGEON_SUB_TALENT"),
                         ["INVALID_ITEM_POOL"])
        self.assertEqual(pool_issues([{"counts": [1], "items": [114001]}], "DUNGEON_SUB_RELIQUARY"),
                         ["RELIQUARY_WEAPON_MATERIAL"])
        self.assertEqual(pool_issues([{"counts": [1, 2], "items": [102], "probabilities": [1]}], None),
                         ["INVALID_PROBABILITIES"])
        self.assertEqual(pool_issues([{"counts": [0], "items": [102]}], None), [])

    def test_native_source_is_only_a_candidate(self):
        graph = {"domains": [
            {"dungeonId": 1, "type": "DUNGEON_DAILY_FIGHT", "subType": "DUNGEON_SUB_TALENT",
             "rootDropId": 10, "rootStatus": "ROOT_PRESENT"},
            {"dungeonId": 2, "type": "DUNGEON_DAILY_FIGHT", "subType": "DUNGEON_SUB_TALENT",
             "rootDropId": 11, "rootStatus": "ROOT_MISSING"},
        ]}
        previews = {"dungeons": [
            {"dungeonId": 1, "previewItems": [{"itemId": 104301, "displayCount": None}]},
            {"dungeonId": 2, "previewItems": [{"itemId": 102, "displayCount": "100"}]},
        ]}
        actual = audit(graph, previews, [{"dungeonId": 2, "drops": [{"counts": [2], "items": []}]}])
        self.assertEqual(actual["summary"]["staticClaimRoutes"],
                         {"NATIVE_ONLY_CANDIDATE": 1, "NO_PAYABLE_SOURCE_IN_DOMAIN_STATUE_PATH": 1})

    def test_pinned_snapshot(self):
        report = json.loads(PATH.read_text(encoding="utf-8"))
        summary = report["summary"]
        self.assertEqual(summary["dungeonRows"], 373)
        self.assertEqual(summary["sourceRootStates"],
                         {"ROOT_PRESENT": 166, "ROOT_MISSING": 140, "NO_POINTER": 67})
        self.assertEqual(summary["proxyStates"],
                         {"ABSENT": 95, "STRUCTURE_INVALID": 16, "STRUCTURE_VALID": 262})
        self.assertEqual(summary["issuesByDungeonIds"]["INVALID_ITEM_POOL"],
                         [5000, 5001, 5002, 5008, 5100, 5101])
        self.assertEqual(len(summary["issuesByDungeonIds"]["RELIQUARY_WEAPON_MATERIAL"]), 10)
        self.assertEqual(len(summary["sourceRootMissingWithInvalidProxy"]), 9)
        self.assertEqual(len(summary["bossRowsWithoutPayableDomainStatueSource"]), 66)
        self.assertEqual(report["source"]["server"]["files"]["data/DungeonDrop.json"]["gitBlobSha"],
                         SERVER_FILES["data/DungeonDrop.json"])
        self.assertTrue(all(r["staticClaimRoute"] != "PREVIEW_FALLBACK" for r in report["dungeons"]))


if __name__ == "__main__":
    unittest.main()
