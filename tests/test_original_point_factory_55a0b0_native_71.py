"""Original Global 7.1 native 0x55A0B0 pointer-list source observations."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "versions/7.1.0-global/analyses/progression/world/7.1-original-point-factory-55a0b0-native-freelist.json"
SCRIPT = ROOT / "scripts/probe-7.1-factory-helper-55a0b0.py"
spec = importlib.util.spec_from_file_location("original_factory_helper_55a0b0", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class Original71FactoryNative55A0B0Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(SOURCE.read_text(encoding="utf-8"))

    def test_verified_original_source_identity(self):
        d = self.data
        self.assertEqual(d["sourceOriginalExecutableSha256"], probe.PROFILE_71.exe_sha256)
        self.assertEqual(d["sourceOriginalMetadataSha256"], probe.PROFILE_71.metadata_sha256)
        self.assertEqual(d["sourceOriginalSampleSha256"],
                         "5d9bca48ad84ed11588c7c14d80e81b92ea0c9424811ebc480caff4d0dd79f1b")
        self.assertEqual(d["originalHelperRva"], "0x55A0B0")
        self.assertEqual(d["originalSampleWindowBytes"], 0x800)
        probe.verify_prior(ROOT / probe.PRIOR)

    def test_exact_original_native_pointer_list_path(self):
        d = self.data
        self.assertFalse(d["sourceOriginalFirstInstructionJumpThunk"])
        self.assertIsNone(d["sourceJumpRedirectIfPresent"])
        self.assertEqual(d["originalFunctionPaddingBoundaryRva"], "0x55A1E8")
        self.assertEqual(d["originalFallbackNativeEntryRva"], "0x55A1F0")
        self.assertEqual(d["originalNativeReturnRva"], "0x55A19E")
        self.assertTrue(d["sourceVerifiedListHeadPopAndReturnedPointerFlow"])
        rows = {x["rva"]: x for x in d["sourceOriginalListPointerChain"]}
        self.assertEqual(rows["0x55A119"]["bytes"], "488b7120")
        self.assertEqual(rows["0x55A12B"]["bytes"], "488b06")
        self.assertEqual(rows["0x55A12E"]["bytes"], "48894120")
        self.assertEqual(rows["0x55A196"]["bytes"], "4889f0")
        self.assertEqual(rows["0x55A19E"]["bytes"], "c3")
        self.assertEqual(rows["0x55A1D5"]["bytes"], "e916000000")

    def test_unproven_semantics_not_promoted(self):
        d = self.data
        for key in ("sourceRuntimeAllocationSemanticsProven",
                    "originalConcreteFactoryCaseClassSlotTypeDefinitionProven",
                    "sourceVirtualReaderPlusF8OwnerProven",
                    "originalScenePointLoaderAndChestPositionOrLevelProven"):
            self.assertFalse(d[key])
        self.assertEqual(d["sourceOriginalRunHeadSha"],
                         "b5b9e9ca879d08081a59ff2faa033004f9a42208")
        self.assertTrue(d["sourceOriginalArtifactDigest"].startswith("sha256:"))


if __name__ == "__main__":
    unittest.main()
