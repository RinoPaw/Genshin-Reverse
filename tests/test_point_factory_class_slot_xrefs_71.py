"""Original 7.1 Scene Point-compatible 31 native element factory class slot audit."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts/probe-7.1-point-factory-class-slot-xrefs.py"
spec=importlib.util.spec_from_file_location("factory_slot71",SCRIPT)
p=importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
REPORT=ROOT/p.ORIGINAL_FACTORY_REPORT


class OriginalFactorySlotReferences(unittest.TestCase):
    def test_original_factory_source_and_exact_numeric_slot_pair(self):
        cases=p.source_factory_slots(REPORT)
        self.assertEqual(len(cases),31)
        self.assertEqual(cases[1]["nativeRuntimeClassSlotRva"],"0x57C37B0")
        self.assertEqual(cases[14]["nativeRuntimeClassSlotRva"],"0x57C1970")
        self.assertEqual(cases[1]["nativeBranchRva"],"0xC591C94")
        self.assertEqual(cases[14]["nativeBranchRva"],"0xC591DF4")
        self.assertEqual(p.TARGET_CASES,(1,14))
        self.assertEqual(len(p.PREFIXES),32)

    def test_pinned_method_index(self):
        with tempfile.TemporaryDirectory() as d:
            file=Path(d)/"methods.csv"
            file.write_bytes(b"untrusted")
            with patch.object(p,"git_blob",return_value="wrong"):
                with self.assertRaisesRegex(ValueError,"Git blob changed"):
                    p.scan(Path("nonexistent"),file,REPORT)

    def test_untrusted_factory_report_fails(self):
        with tempfile.TemporaryDirectory() as d:
            file=Path(d)/"report.json"
            file.write_text('{"originalExeSha256":"WRONG"}',encoding="utf-8")
            with self.assertRaises(KeyError):
                p.source_factory_slots(file)



    def test_source_verified_original_slot_xref_report(self):
        source=(ROOT/"versions/7.1.0-global/analyses/progression/world/"
                "7.1-original-scene-point-factory-1-14-native-class-slot-xrefs.json")
        import json
        j=json.loads(source.read_text(encoding="utf-8"))
        self.assertEqual(j["originalExeSha256"],p.PROFILE_71.exe_sha256)
        self.assertEqual(j["originalMethodMetadataGitBlob"],p.EXPECTED_METHODS_GIT_BLOB)
        self.assertEqual(j["originalNativeFactorySourceSha256"],p.EXPECTED_FACTORY_SHA)
        self.assertEqual(j["originalArchivedAll31CaseResultsArtifactId"],12412125780)
        records=j["nativeClassSlotReferencesByFactoryCase"]
        self.assertEqual(set(records),{"1","14"})
        for key,slot,candidates,aligned in (
            ("1","0x57C37B0",23,21),
            ("14","0x57C1970",50,48)
        ):
            row=records[key]
            self.assertEqual(row["nativeClassSlotRva"],slot)
            self.assertEqual(row["originalRIPByteMatchCount"],candidates)
            self.assertEqual(row["originalAlignedNativeReferenceCount"],aligned)
            self.assertEqual(row["originalMisalignedOrUnverifiedCandidateCount"],2)
            self.assertEqual(len(row["exactOriginalCodeReferences"]),aligned)
            self.assertFalse(row["originalConcreteIL2CPPClassNameIdentified"])
            for x in row["exactOriginalCodeReferences"]:
                self.assertTrue(x["exactOriginalMetadataMethodOwners"])
                self.assertFalse(x["originalClassIdentityFromThisReferenceProven"])
        self.assertEqual(records["1"]["originalNativeReferencedMethodOwnerCounts"]["OAGPJFNDNNG"],2)
        self.assertEqual(records["14"]["originalNativeReferencedMethodOwnerCounts"]["GFIOKOCNMFF"],8)
        self.assertTrue(j["claims"]["nativeAlignedXrefsToCase1And14Proven"])
        for key in ("originalConcreteTypeDefinitionForCase1Proven",
                    "originalConcreteTypeDefinitionForCase14Proven",
                    "originalScenePointAssetLoaderToReaderProven",
                    "originalChestGadgetPlacementOrLevelProven"):
            self.assertFalse(j["claims"][key])

if __name__=="__main__":
    unittest.main()
