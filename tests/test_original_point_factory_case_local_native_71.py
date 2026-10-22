"""Regression for source-original Global 7.1 factory case 1/14 native paths.

The committed original-machine-code observations are fixed positive controls.
They do not establish original Point file loading, chest coordinates, or level.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "scripts/probe-7.1-point-factory-case-local-native.py"
REPORT = ROOT / "versions/7.1.0-global/analyses/progression/world/7.1-original-point-factory-case-1-14-local-native-paths.json"

spec = importlib.util.spec_from_file_location("original_point_factory_local_native", PROBE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class Original71FactoryCaseNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(REPORT.read_text(encoding="utf-8"))

    def test_exact_source_identity_and_existing_factory(self):
        d = self.data
        self.assertEqual(d["originalExeSha256"], probe.PROFILE_71.exe_sha256)
        self.assertEqual(d["originalMetadataSha256"], probe.PROFILE_71.metadata_sha256)
        self.assertEqual(d["originalMethodsGitBlob"], probe.METHODS_GIT_BLOB)
        self.assertEqual(d["sourceNativeWindowSha256"], probe.SOURCE_SHA256)
        self.assertEqual(d["sourceNativeFactoryRva"], f"0x{probe.FACTORY_RVA:X}")
        self.assertEqual(d["sourceNativeFactoryJumpTableRva"], f"0x{probe.TABLE_RVA:X}")
        cases = probe.source_cases(ROOT / probe.FACTORY_REPORT)
        self.assertEqual(len(cases), 31)
        self.assertEqual([x["numericFactoryCase"] for x in d["caseSlices"]], [1, 14])

    def test_direct_original_native_paths_and_exact_ctor_owners(self):
        expected = {
            1: ("0x57C37B0", "0xC591C94", "0xC591DDF", "BHJILFMHGEE", 54542, 436907, "0x138BA180"),
            14: ("0x57C1970", "0xC591DF4", None, "NKJPPNFAEEF", 65289, 527282, "0x8613310"),
        }
        for row in self.data["caseSlices"]:
            number = row["numericFactoryCase"]
            slot, start, mid, owner, typedef, method, ctor_rva = expected[number]
            with self.subTest(case=number):
                self.assertEqual((row["originalClassSlotRva"], row["originalCaseBranchRva"]), (slot, start))
                flow = row["sourceDirectJumpFollow"]
                self.assertEqual(flow["stopped"], "SOURCE_RET")
                steps = flow["sourceSteps"]
                self.assertEqual(steps[0]["rva"], start)
                self.assertEqual(steps[0]["mnemonic"], "mov")
                self.assertEqual(steps[0]["bytes"],
                    "488b0d151b23f9" if number == 1 else "488b0d75fb22f9")
                if mid:
                    self.assertEqual(steps[1]["directTargetRva"], mid)
                calls = [x for x in steps if x["mnemonic"] == "call"]
                self.assertEqual(len(calls), 2)
                self.assertEqual(calls[0]["directTargetRva"], "0x529A10")
                self.assertEqual(calls[0]["exactOriginalMethodStartOwners"], [])
                self.assertEqual(calls[1]["directTargetRva"], ctor_rva)
                self.assertEqual(calls[1]["exactOriginalMethodStartOwners"], [{
                    "typeName": owner, "methodName": ".ctor", "methodIndex": method,
                    "typeDefinitionIndex": typedef,
                }])
                self.assertEqual(steps[-1]["mnemonic"], "ret")
                self.assertFalse(row["sourceCaseConcreteTypeDefinitionProven"])
                self.assertFalse(row["sourceVtablePlusF8MethodOwnerProven"])

    def test_unproven_runtime_and_scene_claims_stay_unproven(self):
        d = self.data
        self.assertFalse(d["originalRuntimeAllocatorFunctionSemanticsProven"])
        self.assertFalse(d["originalClassSlotConcreteTypeDefinitionProven"])
        self.assertFalse(d["originalScenePointFileLoaderOrInstancePlacementProven"])
        self.assertIn("Original chest instance position or level", d["unproven"])


if __name__ == "__main__":
    unittest.main()
