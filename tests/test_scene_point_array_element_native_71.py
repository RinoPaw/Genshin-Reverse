"""Verify exact original 7.1 array element dispatch evidence boundaries."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
FILE=ROOT/"scripts/probe-7.1-scene-point-array-element-native.py"
spec=importlib.util.spec_from_file_location("array_element_71",FILE)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Original71ArrayElementEvidence(unittest.TestCase):
    def test_original_native_source_anchors(self):
        p=json.loads((ROOT/m.PRIOR).read_text(encoding="utf-8"))
        self.assertEqual(p["originalExeSha256"],m.PROFILE_71.exe_sha256)
        self.assertTrue(p["originalNativeConditionalReadProof"]["sourceNativeHelperConsumesExactlyOneByteFor0xCB"])
        self.assertEqual(m.RVA,0xAD23000)
        self.assertEqual(m.INDIRECT_RVA,0xAD230BB)
        self.assertEqual(m.SOURCE_SHA,"6319613278adf382bf7ce513d1d875ef98b318d5f5f3bc9c423b72caebd7c0ad")

    def test_original_git_blob_is_required(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"methods.csv"
            p.write_text("type_name,method_name\nNLDEPJEOJGC,GMENPOPMKAA\n",encoding="utf-8")
            with patch.object(m,"git_blob",return_value="invalid"):
                with self.assertRaisesRegex(ValueError,"metadata Git blob drift"):
                    m.metadata_members(p,"method")


    def test_exact_original_31_case_polymorphic_factory_evidence(self):
        evidence=(ROOT/"versions/7.1.0-global/analyses/progression/world/"
                 "7.1-original-scene-point-array-element-factory-native-evidence.json")
        report=json.loads(evidence.read_text(encoding="utf-8"))
        self.assertEqual(report["originalExeSha256"],m.PROFILE_71.exe_sha256)
        self.assertEqual(report["originalMethodsGitBlob"],m.METHODS_BLOB)
        self.assertEqual(report["originalFieldsGitBlob"],m.FIELDS_BLOB)
        self.assertEqual(report["runArtifactId"],12409798011)
        reader=report["originalArrayNativeReader"]
        self.assertEqual(reader["nativeSourceWindowSha256"],m.SOURCE_SHA)
        self.assertEqual(reader["typeDefinitionIndex"],63768)
        self.assertEqual(reader["elementDiscriminatorSourceByteReadRva"],"0xAD23393")
        self.assertEqual(reader["elementFactoryDirectCallRva"],"0xAD233A5")
        self.assertEqual(reader["elementVirtualReaderCallRva"],"0xAD233BE")
        self.assertEqual(reader["elementVirtualReaderSlotOffset"],"0xF8")
        fac=report["originalFactory"]
        self.assertEqual(fac["originalSourceWindowSha256"],m.FACTORY_SOURCE_SHA)
        self.assertEqual(fac["originalSourceBytes"],1200)
        self.assertEqual(fac["nativeSourceCodeLinearDecodedInstructions"],235)
        self.assertEqual(fac["originalJumpTableRva"],f"0x{m.FACTORY_TABLE_RVA:X}")
        self.assertEqual(fac["exactAlignedNativeJumpCaseCount"],31)
        self.assertEqual([x["originalNumericCaseId"] for x in fac["sourceCases"]],
                         list(range(31)))
        self.assertTrue(all(x["nativeRuntimeClassSlotRva"].startswith("0x")
                            for x in fac["sourceCases"]))
        self.assertEqual(fac["sourceCases"][0]["nativeBranchRva"],"0xC591C7C")
        for flag in ("eachNumericCaseConcreteIL2CPPClassResolved",
                     "originalScenePointFileConsumerLinked",
                     "originalPointElementsFullyConsumed",
                     "chestGadgetInstanceCoordinatesRecovered",
                     "chestLevelSemanticsRecovered",
                     "serverClientChestPlacementOwnershipProven"):
            self.assertFalse(report["claims"][flag])

if __name__=="__main__":
    unittest.main()
