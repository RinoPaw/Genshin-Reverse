"""Regression checks: AstaPS B-level conditional 3/4-substat DropTable semantics."""

from __future__ import annotations

import json
import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/audit-7.1-reliquary-asta-consumer.py"
OUTPUT = (ROOT / "versions/7.1.0-global/windows-x64/analyses"
          / "artifact-generation/7.1-reliquary-asta-weight-consumer.json")


class ReliquaryAstaConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = runpy.run_path(str(SCRIPT))
        cls.snapshot = json.loads(OUTPUT.read_text(encoding="utf-8"))

    def test_source_commit_and_weight_evidence_boundary(self):
        out = self.snapshot
        self.assertEqual(out["confidence"], "B_SERVER_IMPLEMENTATION_CONDITIONAL")
        self.assertEqual(out["source"]["astaPSCommit"],
                         "dcf04369a356486a07be976b244b83d7208c3992")
        self.assertEqual(out["source"]["astaPSFiles"], self.mod["SERVER_FILES"])
        self.assertEqual(out["source"]["reverseGitBlobs"],
                         self.mod["REQUIRED_INPUT_BLOBS"])
        self.assertEqual(out["executor"]["choiceType"], 0)
        self.assertIn("Not a proof of official", out["scope"])
        self.assertEqual(out["summary"]["directRuntimeClaimsObserved"], 0)

    def test_27_dungeons_are_native_with_proxy_fallback(self):
        rows = self.snapshot["dungeons"]
        self.assertEqual(len(rows), 27)
        self.assertEqual(len({r["dungeonId"] for r in rows}), 27)
        self.assertEqual(len({r["choiceNodeId"] for r in rows}), 27)
        for r in rows:
            with self.subTest(dungeonId=r["dungeonId"]):
                self.assertEqual(r["sourceClaimRoute"],
                                 "NATIVE_WITH_PROXY_FALLBACK_CANDIDATE")
                self.assertEqual(r["configuredWeights"], {"3": 8000, "4": 2000})
                self.assertEqual(r["conditionalAstaPSProbability"],
                                 {"3": "4/5", "4": "1/5"})
        example = next(r for r in rows if r["dungeonId"] == 5052)
        self.assertEqual(example["rootDropId"], 85144500)
        self.assertEqual(example["choiceNodeId"], 85144515)

    def test_exhaustive_cumulative_selection_boundary(self):
        # Independent finite-space verification of the pinned Java algorithm:
        # rand.nextInt(10000), then first cumulative weight greater than target.
        bins = [0, 0]
        for draw in range(10000):
            cumulative = 0
            for i, weight in enumerate((8000, 2000)):
                cumulative += weight
                if draw < cumulative:
                    bins[i] += 1
                    break
        self.assertEqual(bins, [8000, 2000])
        self.assertEqual(self.snapshot["executor"]["conditionalThreeFraction"], "4/5")
        self.assertEqual(self.snapshot["executor"]["conditionalFourFraction"], "1/5")

    def test_exact_rebuild_from_pinned_research_inputs(self):
        mod = self.mod
        weights = mod["read_pinned"](
            mod["WEIGHTS"], mod["REQUIRED_INPUT_BLOBS"]["variantBranches"]
        )
        claims = mod["read_pinned"](
            mod["CLAIMS"], mod["REQUIRED_INPUT_BLOBS"]["staticClaimRoutes"]
        )
        self.assertEqual(mod["build_snapshot"](weights, claims), self.snapshot)

    def test_reject_unexpected_runtime_claim_route(self):
        import copy
        mod = self.mod
        weights = mod["read_pinned"](
            mod["WEIGHTS"], mod["REQUIRED_INPUT_BLOBS"]["variantBranches"]
        )
        claims = copy.deepcopy(mod["read_pinned"](
            mod["CLAIMS"], mod["REQUIRED_INPUT_BLOBS"]["staticClaimRoutes"]
        ))
        target = self.snapshot["dungeons"][0]["dungeonId"]
        row = next(x for x in claims["dungeons"] if x["dungeonId"] == target)
        row["staticClaimRoute"] = "PROXY_ONLY_CANDIDATE"
        with self.assertRaisesRegex(ValueError, "source-choice route changed"):
            mod["build_snapshot"](weights, claims)


if __name__ == "__main__":
    unittest.main()
