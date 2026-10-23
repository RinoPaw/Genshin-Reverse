"""Regression for exact Global 7.1 native 0x55A1F0 fallback source CFG.

No client binary is downloaded during ordinary CI. The committed original
source machine observations are pinned with hash and RVA witnesses.
"""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/probe-7.1-point-factory-fallback-55a1f0-cfg.py"
REPORT = ROOT / "versions/7.1.0-global/analyses/progression/world/7.1-original-factory-fallback-55a1f0-source-cfg.json"
spec = importlib.util.spec_from_file_location("original_71_fallback_55a1f0", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class Original71FactoryFallback55A1F0(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = json.loads(REPORT.read_text(encoding="utf-8"))

    def test_previous_original_client_tail_jump(self):
        probe.verify_prior(ROOT / probe.PRIOR)
        self.assertEqual(self.d["originalExeSha256"], probe.PROFILE_71.exe_sha256)
        self.assertEqual(self.d["originalMetadataSha256"], probe.PROFILE_71.metadata_sha256)
        self.assertEqual(self.d["sourcePrior"], probe.PRIOR)
        self.assertEqual(self.d["sourceOriginalNativeCallerJumpRva"], "0x55A1D5")
        self.assertEqual(self.d["originalNativeFallbackRva"], "0x55A1F0")
        self.assertEqual(self.d["sourceOriginalWindowSha256"],
                         "7ecaf3a1e7dc075f775f2925ef497e73428736c9e0ec312b8be94a0a56ae03a9")
        self.assertTrue(self.d["sourceOriginalFallbackPrefixHex"].startswith("4157415641554154"))

    def test_original_reachable_machine_cfg(self):
        flow = self.d["sourceNativeReachableCFG"]
        self.assertEqual(flow["sourceNativeEntryRva"], "0x55A1F0")
        self.assertEqual(flow["inspectedSourceWindowBytes"], 0x400)
        self.assertEqual(flow["sourceWindowSha256"], self.d["sourceOriginalWindowSha256"])
        self.assertEqual(flow["reachableDecodedOriginalInstructions"], 222)
        self.assertEqual(flow["returnCount"], 1)
        self.assertEqual(flow["originalDecodedReturnSites"], [{
            "rva": "0x55A573", "mnemonic": "ret", "operands": "", "bytes": "c3"
        }])
        self.assertEqual(flow["directCallCount"], 15)
        self.assertEqual(flow["indirectCallCount"], 2)
        self.assertEqual(flow["unresolvedNativeBranchOrDecodeCount"], 0)
        self.assertEqual(flow["terminalJumps"], [])
        self.assertTrue(flow["verifiedCompleteWithinWindow"])
        self.assertEqual(flow["firstReachableInstructions"][0]["rva"], "0x55A1F0")
        self.assertEqual(flow["firstReachableInstructions"][0]["bytes"], "4157")
        self.assertIn("0x55A590", {x["targetRva"] for x in flow["directCalls"]})
        self.assertIn("0x55A630", {x["targetRva"] for x in flow["directCalls"]})
        self.assertIn("0x55AAB0", {x["targetRva"] for x in flow["directCalls"]})
        self.assertIn("0x55A573", {x["rva"] for x in self.d["sourceNativeLastInstructions"]})

    def test_unproven_type_and_scene_links(self):
        for key in (
            "originalNativeAllocationSemanticProven",
            "originalRuntimeFactorySlotConcreteTypeProven",
            "originalFactoryVirtualReaderPlusF8Resolved",
            "originalScenePointFileLoaderOrChestCoordinatesLevelProven",
        ):
            self.assertFalse(self.d[key])
        self.assertEqual(self.d["sourceOriginalRunHeadSha"],
                         "7a1aa0e9c614114c854fa22ae99d9815d3d59878")
        self.assertTrue(self.d["sourceOriginalArchiveDigest"].startswith("sha256:"))


if __name__ == "__main__":
    unittest.main()
