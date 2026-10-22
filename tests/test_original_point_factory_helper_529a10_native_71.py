"""Regression: original Global 7.1 factory case 1/14 shared native helper.

Tests only retained SHA-pinned original EXE evidence. Protected/indirect
callee identity and native allocator semantics remain unproven.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/probe-7.1-point-factory-helper-529a10.py"
SOURCE = ROOT / "versions/7.1.0-global/analyses/progression/world/7.1-original-point-factory-helper-529a10-native.json"
spec = importlib.util.spec_from_file_location("original71_factory_helper", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class Original71NativeHelper529A10(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(SOURCE.read_text(encoding="utf-8"))

    def test_original_sample_and_previous_case_paths(self):
        d = self.data
        self.assertEqual(d["originalExecutableSha256"], probe.PROFILE_71.exe_sha256)
        self.assertEqual(d["originalMetadataSha256"], probe.PROFILE_71.metadata_sha256)
        self.assertEqual(d["sourceOriginalCasesUsingTarget"], [1, 14])
        self.assertEqual(d["sharedNativeHelperRva"], "0x529A10")
        self.assertEqual(d["originalSourceNativeWindowSha256"],
                         "efaaef4a2f37f1aa56278c1f8981aa4b05b788ae0cbf42956e5f678a17080868")
        prior = probe.prior_controls(ROOT / probe.PRIOR)
        self.assertEqual(len(prior["caseSlices"]), 2)

    def test_original_helper_source_code_and_return(self):
        d = self.data
        self.assertFalse(d["originalFirstInstructionIsDirectJumpThunk"])
        self.assertIsNone(d["sourceRedirectIfThunk"])
        self.assertEqual(d["originalSourcePaddingBoundaryRva"], "0x529BB4")
        self.assertEqual(d["originalReturnInstructionRvas"], ["0x529B5A"])
        self.assertTrue(d["originalDataFlowVia55A0B0ReturnRdiToRaxVerified"])
        native = {x["rva"]: x for x in d["originalSourceWitnessedSharedHelperDataFlow"]}
        self.assertEqual(native["0x529B2D"]["bytes"], "4889c7")
        self.assertEqual(native["0x529B50"]["bytes"], "4889f8")
        self.assertEqual(native["0x529B5A"]["bytes"], "c3")
        calls = [x for x in d["sourceCallSites"] if x["sourceDirectTargetRva"] == "0x55A0B0"]
        self.assertEqual([x["rva"] for x in calls], ["0x529ABC", "0x529B28"])
        self.assertIn("0x50D9C0", {x["sourceDirectTargetRva"] for x in d["sourceCallSites"]})
        self.assertIn("0x51CD50", {x["sourceDirectTargetRva"] for x in d["sourceCallSites"]})

    def test_unresolved_runtime_and_scene_boundary(self):
        d = self.data
        for key in (
            "source55A0B0ActualAllocationSemanticsVerified",
            "originalNativeHelperProvenObjectAllocator",
            "sourceFactoryCaseClassPointerToTypeDefinitionResolved",
            "originalScenePointLoaderOrChestPositionLevelProven",
        ):
            self.assertFalse(d[key])
        self.assertEqual(d["sourceOriginalRunHeadSha"],
                         "95a3878aa27f3fdd001e902ef03c2d03a6f28509")
        self.assertTrue(d["sourceOriginalArchiveArtifactDigest"].startswith("sha256:"))


if __name__ == "__main__":
    unittest.main()
