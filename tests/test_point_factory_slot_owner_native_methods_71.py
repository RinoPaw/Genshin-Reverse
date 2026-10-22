"""Tests for original Global 7.1 factory class-slot method owners."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts/probe-7.1-point-factory-slot-owner-native-methods.py"
spec=importlib.util.spec_from_file_location("scene_point_slot_owner_71",SCRIPT)
p=importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class OriginalFactorySlotOwnerNativeMethods(unittest.TestCase):
    def test_exact_original_source_slots_and_methods(self):
        j=json.loads((ROOT/p.SOURCE_REPORT).read_text(encoding="utf-8"))
        self.assertEqual(j["originalExeSha256"],p.PROFILE_71.exe_sha256)
        self.assertEqual(j["originalMethodMetadataGitBlob"],p.METHODS_BLOB)
        self.assertEqual(p.SLOTS,{1:0x57C37B0,14:0x57C1970})
        self.assertEqual(len(p.TARGET_OWNERS),3)
        for case,owner,index,rva,sites in p.TARGET_OWNERS:
            self.assertEqual({int(x["instructionRva"],16) for x in
              j["nativeClassSlotReferencesByFactoryCase"][str(case)]["exactOriginalCodeReferences"]
              if x["exactOriginalMetadataMethodOwners"][0]["originalTypeName"]==owner
              and x["exactOriginalMetadataMethodOwners"][0]["originalMethodName"]=="JOBDNGNICNC"},set(sites))
        self.assertEqual(sum(len(row[-1]) for row in p.TARGET_OWNERS),4)

    def test_metadata_source_identity_is_required(self):
        with tempfile.TemporaryDirectory() as temp:
            fake=Path(temp)/"methods.csv"
            fake.write_text("bad data",encoding="utf-8")
            with patch.object(p,"git_blob",return_value="wrong"):
                with self.assertRaisesRegex(ValueError,"methods CSV blob drift"):
                    p.validate_sources(fake,ROOT/p.SOURCE_REPORT)



    def test_original_method_windows_and_runtime_unbacked_class_slots(self):
        evidence=(ROOT/"versions/7.1.0-global/analyses/progression/world/"
                  "7.1-original-point-factory-class-slot-runtime-checks.json")
        report=json.loads(evidence.read_text(encoding="utf-8"))
        self.assertEqual(report["originalExeSha256"],p.PROFILE_71.exe_sha256)
        self.assertEqual(report["originalMethodsGitBlob"],p.METHODS_BLOB)
        self.assertEqual(report["sourceRunArtifactId"],12413260323)
        rows=report["originalMethodWindows"]
        self.assertEqual(len(rows),3)
        self.assertEqual([x["originalDeclaringTypeName"] for x in rows],
                         ["OAGPJFNDNNG","BFLGIHGLPBF","NDPMDLJEOLG"])
        self.assertEqual([x["originalDecodedInstructionCount"] for x in rows],
                         [239,132,370])
        self.assertEqual([x["originalNativeWindowSha256"] for x in rows],
                         ["f47dfc35e1bc65bcf1ba9919bd4a0e181ed640dce07b64b8f998b766102a6775",
                          "c3749fdc218f02d9431b77c19e75951816986052cce57c1df1fa395ea4e746e1",
                          "eca3756ec42511bee71cf1a13305028d1e17799663e3309e4cbcb93a27d767d1"])
        self.assertEqual([len(x["sourceOriginalClassSlotLoadWitnesses"]) for x in rows],
                         [2,1,1])
        for row in rows:
            self.assertFalse(row["originalSlotClassIdentityProven"])
            self.assertTrue(all(not x["classSlotIsKnownToContainThisOriginalDeclaringType"]
                                for x in row["sourceOriginalClassSlotLoadWitnesses"]))
        slots=report["originalDirectNativeGlobalSlotWriteAudit"]
        self.assertEqual([slots[str(k)]["originalStaticClassSlotRva"] for k in (1,14)],
                         ["0x57C37B0","0x57C1970"])
        for row in slots.values():
            self.assertEqual(row["sourcePESection"],".data")
            self.assertFalse(row["sourceSlotFileBackedQword"])
            self.assertIsNone(row["sourceStaticSlotBytes"])
            self.assertEqual(row["originalVerifiedAlignedNativeRipStores"],0)
            self.assertFalse(row["originalConcreteTypeDefinitionIndexProven"])
        for key in report["unresolved"].values():
            self.assertFalse(key)

if __name__=="__main__":
    unittest.main()
