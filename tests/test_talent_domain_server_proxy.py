"""Offline pinned AstaPS talent-domain fallback evidence checks."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

BASE = (Path(__file__).resolve().parents[1] /
        "versions/7.1.0-global/analyses/progression/economy")


class ServerProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = json.loads((BASE / "7.1-talent-domain-drop-links.json").read_text(encoding="utf-8"))
        cls.b = json.loads((BASE / "7.1-talent-domain-server-proxy.json").read_text(encoding="utf-8"))

    def test_evidence_source(self):
        self.assertIn("NOT 7.1 native", self.b["evidence"])
        self.assertEqual(self.b["source"]["gitBlobSha"],
                         "7fdd3b01d7b4fedc5837eae776502aeffc2fe3ed")
        self.assertEqual(self.b["source"]["commit"],
                         "b1c5af21a26deaaa9983f485d98cd32e5693e64e")
        self.assertEqual(self.b["source"]["wholeFileRowCount"], 266)

    def test_domain_coverage(self):
        domains = {x["dungeonId"]: x for x in self.a["domains"]}
        rows = self.b["dungeons"]
        ids = {x["dungeonId"] for x in rows}
        self.assertEqual(len(ids), len(rows))
        self.assertEqual(len(rows), 96)
        self.assertTrue(ids <= set(domains))
        self.assertEqual(sum(not domains[i]["rootPresent"] for i in ids), 48)
        self.assertEqual(self.b["summary"]["serverOnlyRows"], 48)
        self.assertEqual(self.b["summary"]["withNativeRootAndProxy"], 48)
        self.assertEqual(self.b["summary"]["withoutServerProxy"],
                         [4200, 4201, 4202, 4203, 5250, 5251, 5252, 5253])
        self.assertNotIn("comment", next(x for x in rows if x["dungeonId"] == 4651))
        self.assertIn("comment", next(x for x in rows if x["dungeonId"] == 4213))

    def test_raw_server_entries(self):
        for row in self.b["dungeons"]:
            with self.subTest(dungeon=row["dungeonId"]):
                self.assertTrue(row["drops"])
                for drop in row["drops"]:
                    self.assertTrue(drop["counts"])
                    self.assertTrue(drop["items"])


if __name__ == "__main__":
    unittest.main()
