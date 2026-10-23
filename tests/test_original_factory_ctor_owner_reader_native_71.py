"""Exact original Global 7.1 factory constructor-owner and native-reader evidence.

Regular CI pins committed SHA-verified original metadata/native observations
without fetching the client, or asserting any Scene/Point/chest meaning.
"""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts/probe-7.1-point-factory-ctor-type-declarations.py"
REPORT=ROOT/"versions/7.1.0-global/analyses/progression/world/7.1-original-point-factory-case-1-14-ctor-owner-reader-native.json"
spec=importlib.util.spec_from_file_location("original_71_ctor_types",SCRIPT)
probe=importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class Original71FactoryCtorOwnerReader(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=json.loads(REPORT.read_text(encoding="utf-8"))

    def test_exact_source_and_existing_case_proof(self):
        d=self.data
        probe.source_cases(ROOT/probe.CASE_REPORT)
        self.assertEqual(d["sourceOriginalExeSha256"],probe.PROFILE_71.exe_sha256)
        self.assertEqual(d["sourceOriginalMetadataSha256"],probe.PROFILE_71.metadata_sha256)
        self.assertEqual(d["sourceOriginalMethodsBlob"],probe.METHODS_BLOB)
        self.assertEqual(d["sourceOriginalFieldsBlob"],probe.FIELDS_BLOB)
        self.assertEqual(d["sourcePreviousCaseEvidence"],probe.CASE_REPORT)
        self.assertEqual([x["originalFactoryNumericCase"] for x in d["originalCaseOwnerDeclarations"]],[1,14])

    def test_original_ctor_types_fields_and_reader_method_anchors(self):
        observed={
            1:("BHJILFMHGEE",54542,436907,"0x138BA180","0x138B9390",436910,13,4,
               "638ab9a9d9bc9bf8a3d2661e29c6e0f2f3f928973d1221ed10eb9d43535a9376",3568),
            14:("NKJPPNFAEEF",65289,527282,"0x8613310","0x8613440",527284,16,4,
                "bb16ab2a183ad6c73c843631f6db47168a9d8f6ca866b851e7bef3af3e50c8b6",4944),
        }
        for row in self.data["originalCaseOwnerDeclarations"]:
            case=row["originalFactoryNumericCase"]
            name,typedef,ctor_index,ctor_rva,reader_rva,reader_index,fields,methods,sha,size=observed[case]
            with self.subTest(case=case):
                self.assertEqual(row["originalConstructorType"],name)
                self.assertEqual(row["originalConstructorTypeDefinitionIndex"],typedef)
                self.assertEqual(row["originalConstructorMethodIndex"],ctor_index)
                self.assertEqual(row["sourceNativeCtorRva"],ctor_rva)
                self.assertEqual(row["originalDeclaredFieldCount"],fields)
                self.assertEqual(row["originalDeclaredMethodCount"],methods)
                self.assertEqual(len(row["sourceGMENPOPMKAADeclarations"]),1)
                r=row["sourceOriginalGMENPOPMKAANativeMethod"]
                self.assertEqual(r["sourceOriginalMethodRva"],reader_rva)
                self.assertEqual(r["sourceOriginalMethodIndex"],reader_index)
                self.assertEqual(r["sourceWindowBytes"],size)
                self.assertEqual(r["sourceWindowSha256"],sha)
                self.assertFalse(r["sourceReaderVtableSlotF8MappingProven"])
                self.assertFalse(row["nativeClassSlotToConcreteTypeProven"])

    def test_source_original_case14_direct_reader_delegation(self):
        row=self.data["sourceExactCase14ReaderDirectCallToCase1Reader"]
        self.assertEqual(row,{
            "rva":"0x8613469","mnemonic":"call",
            "operands":"0x1538b9390","bytes":"e8225f2a0b"
        })
        self.assertTrue(self.data["sourceNativeReaderCodeDelegationVerified"])
        self.assertFalse(self.data["sourceNativeReaderVtableBindingVerified"])

    def test_no_unproven_scene_claim_promoted(self):
        for name in ("sourceFactoryClassSlotToExactRuntimeClassProven",
                     "sourceFactoryVtableSlotF8MethodOwnerProven",
                     "originalScenePointLoaderOrChestCoordinatesLevelProven"):
            self.assertFalse(self.data[name])
        self.assertEqual(self.data["sourceOriginalRunHeadSha"],
                         "319790859d430e107004e2b3aba337321b4bf00b")
        self.assertTrue(self.data["sourceOriginalArtifactDigest"].startswith("sha256:"))


if __name__=="__main__":
    unittest.main()
