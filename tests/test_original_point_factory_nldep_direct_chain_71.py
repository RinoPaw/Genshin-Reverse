"""Strict Global 7.1 native factory reader to NLDEP one-arg call evidence.

Original source protected binary identities and exact negative native direct
call test remain pinned without downloading original samples during normal CI.
"""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts/probe-7.1-point-factory-nldep-overloads-native.py"
REPORT=ROOT/"versions/7.1.0-global/analyses/progression/world/7.1-original-point-factory-14-1-nldep-direct-reader-chain.json"
spec=importlib.util.spec_from_file_location("original71_factory_nldep",SCRIPT)
probe=importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class Original71FactoryNLDEPChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d=json.loads(REPORT.read_text(encoding="utf-8"))

    def test_provenance_and_distinct_overloads(self):
        x=self.d
        self.assertEqual(x["originalExeSha256"],probe.PROFILE_71.exe_sha256)
        self.assertEqual(x["originalMetadataSha256"],probe.PROFILE_71.metadata_sha256)
        self.assertEqual(x["originalOneArgReaderOwner"],"NLDEPJEOJGC")
        self.assertEqual(x["originalOneArgReaderTypeDefinitionIndex"],63768)
        self.assertEqual(x["originalOneArgReaderMethodIndex"],514422)
        self.assertEqual(x["originalTwoArgArrayReaderMethodIndex"],514423)
        self.assertEqual(x["originalOneArgReaderNativeRva"],"0xAD22310")
        self.assertEqual(x["originalTwoArgArrayReaderNativeRva"],"0xAD23000")
        self.assertEqual(x["sourceTwoArgPositiveControlSha256"],probe.TWO_ARG_SOURCE_SHA)
        self.assertEqual(probe.provenance(ROOT/probe.PRIOR,ROOT/probe.ARRAY_PRIOR),
                         x["sourceFactoryToNLDEPDirectCallChain"])

    def test_exact_machine_code_bounds_and_explicit_missing_direct_overload_call(self):
        x=self.d
        self.assertEqual(x["sourceOneArgWindowBytes"],0xCF0)
        self.assertEqual(x["sourceOneArgWindowSha256"],
                         "07658f6b1e8111e4629b50b6ac8d73721da69208c89d998df5abf58bb5c7a856")
        self.assertEqual(x["sourceOneArgDecodedLinearInstructions"],755)
        self.assertEqual(len(x["sourceOneArgNativeDirectCalls"]),59)
        self.assertEqual(len(x["sourceOneArgNativeIndirectCalls"]),1)
        self.assertEqual(x["sourceOneArgDirectCallsIntoTwoArgNativeReader"],[])
        self.assertFalse(x["sourceDirectOneArgToTwoArgNativeCallProven"])
        self.assertEqual([r["rva"] for r in x["sourceOneArgNativeReturnCandidates"]],
                         ["0xAD22CBB","0xAD22FF6"])
        self.assertEqual(x["sourceOneArgNativeFirstInstructions"][0]["rva"],"0xAD22310")
        self.assertNotIn("0xAD23000",
                         {row["targetRva"] for row in x["sourceOneArgNativeDirectCalls"]})

    def test_no_vtable_loader_or_chest_claim(self):
        for name in ("sourceFactoryVirtualReaderF8TargetProven",
                     "sourcePointAssetLoaderToNativeChainProven",
                     "originalChestCoordinatesAndLevelProven"):
            self.assertFalse(self.d[name])
        self.assertEqual(self.d["sourceOriginalRunHeadSha"],
                         "b1ff982e964e0dc2905b1d89a9e0d89dbc22c88f")
        self.assertTrue(self.d["sourceOriginalArtifactDigest"].startswith("sha256:"))


if __name__=="__main__":
    unittest.main()
