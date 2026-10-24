"""Regression of exact Global 7.1 native caller input to parent-reader byte stream.

Original EXE is downloaded only by the one-time research workflow. This test
pinpoints the two original callee declaring methods, their SHA-256 byte
windows, and source machine instructions transferring a returned reader
object from GCJPJCKPGLI to the parent method. No official Scene/Point resource
loader identity or chest location/level is asserted.
"""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts/probe-7.1-point-parent-pre-input-native.py"
NEW=ROOT/"versions/7.1.0-global/analyses/progression/world/7.1-original-scene-parent-native-pre-input-callees.json"
OLD=ROOT/"versions/7.1.0-global/analyses/progression/world/7.1-original-point-parent-reader-kllng-consumer-native.json"
spec=importlib.util.spec_from_file_location("original71_pre_parent_inputs",SCRIPT)
probe=importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class Original71PreParentInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d=json.loads(NEW.read_text(encoding="utf-8"))
        cls.prior=json.loads(OLD.read_text(encoding="utf-8"))

    def test_original_source_samples_and_previous_method_anchors(self):
        d=self.d
        probe.verify_prior(OLD)
        self.assertEqual(d["originalExeSha256"],probe.PROFILE_71.exe_sha256)
        self.assertEqual(d["originalMetadataSha256"],probe.PROFILE_71.metadata_sha256)
        self.assertEqual(d["originalMethodsGitBlob"],probe.caller.METHODS_BLOB)
        self.assertEqual(d["sourceOriginalConsumerNativeSha256"],probe.SOURCE_OWNER_SHA)
        self.assertEqual(d["sourceOriginalConsumerNativeRva"],"0xF04F350")
        self.assertEqual(d["sourceOriginalRunHeadSha"],"420b0fd3dd3a2c52d88b91892ab06db5660e0f42")
        self.assertTrue(d["sourceOriginalArchiveDigest"].startswith("sha256:"))

    def test_original_generated_method_owner_for_input_name(self):
        k=self.d["sourceNativePreParentReaderDirectCallees"]["source_original_uint32_lookup"]
        self.assertEqual(k["sourceOriginalTargetRva"],"0xF06A600")
        self.assertEqual(k["sourceOriginalExactMethodStartOwners"][0]["typeName"],"KLLNGCPBLMM")
        self.assertEqual(k["sourceOriginalExactMethodStartOwners"][0]["methodName"],"FGDNHNBPCKA")
        self.assertEqual(k["sourceOriginalExactMethodStartOwners"][0]["methodIndex"],615966)
        self.assertEqual(k["sourceOriginalExactMethodStartOwners"][0]["parameterTypes"],'["uint32"]')
        self.assertEqual(k["sourceWindowSize"],144)
        self.assertEqual(k["sourceWindowSha256"],
          "30aa25a225ed483582a124a4bb9167f34bb1354b1b8c2e2fa8f4ae21961340b2")
        self.assertEqual([x["rva"] for x in k["sourceOriginalDirectCallSites"]],
                         ["0xF04F3C7","0xF04F40A"])

    def test_original_generated_method_owner_for_string_and_integer_consumer(self):
        k=self.d["sourceNativePreParentReaderDirectCallees"]["source_original_lookup_result_consumer"]
        self.assertEqual(k["sourceOriginalTargetRva"],"0x1016E3F0")
        self.assertEqual(k["sourceOriginalExactMethodStartOwners"][0]["typeName"],"PMOALIJHONP")
        self.assertEqual(k["sourceOriginalExactMethodStartOwners"][0]["methodName"],"GCJPJCKPGLI")
        self.assertEqual(k["sourceOriginalExactMethodStartOwners"][0]["methodIndex"],420370)
        self.assertEqual(k["sourceOriginalExactMethodStartOwners"][0]["parameterTypes"],'["string","int32","int32"]')
        self.assertEqual(k["sourceWindowSize"],336)
        self.assertEqual(k["sourceWindowSha256"],
          "87061bba87ceb2983cf61ae6e9903a5c9ba986def3841ddf82670a452cc2ff73")
        self.assertEqual([x["rva"] for x in k["sourceOriginalDirectCallSites"]],
                         ["0xF04F3D4","0xF04F417"])

    def test_native_record_fields_and_direct_return_argument_transfer(self):
        reader=self.d["sourceNativePreParentReaderDirectCallees"]["source_original_lookup_result_consumer"]
        machine={x["rva"]:(x["mnemonic"],x["operands"],x["bytes"])
                 for x in reader["sourceOriginalEntryInstructions"]}
        for address,expected in {
            "0x1016E4C1":("mov","dword ptr [rsi + 0x1c], eax","89461c"),
            "0x1016E4C4":("mov","qword ptr [rsi + 0x20], rdi","48897e20"),
            "0x1016E4C8":("mov","rax, rsi","4889f0"),
            "0x1016E4D3":("ret","","c3"),
        }.items():
            self.assertEqual(machine[address],expected)
        native={x["rva"]:(x["mnemonic"],x["operands"],x["bytes"])
                for x in self.prior["sourceOriginalParentCallContext"]}
        for address,expected in {
            "0xF04F417":("call","0x15016e3f0","e8d4ef1101"),
            "0xF04F41C":("mov","r14, rax","4989c6"),
            "0xF04F4B2":("mov","rdx, r14","4c89f2"),
            "0xF04F4B5":("call","0x14ee66b20","e86676e1ff"),
        }.items():
            self.assertEqual(native[address],expected)
        path=[x for x in self.prior["sourceOriginalParentCallContext"]
              if 0xF04F41C<=int(x["rva"],16)<=0xF04F4B5]
        self.assertEqual([x["rva"] for x in path
            if x["mnemonic"]=="mov" and x["operands"].startswith("r14,")],["0xF04F41C"])

    def test_no_scene_point_or_chest_semantic_promotion(self):
        for name in ("sourceOriginalScenePointResourceLoaderIdentified",
                     "sourceOriginalFileToParserByteProvenanceVerified",
                     "sourceOriginalChestPositionsOrInstanceLevelVerified"):
            self.assertFalse(self.d[name])


if __name__=="__main__":unittest.main()
