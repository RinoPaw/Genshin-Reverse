"""Source and uncertainty boundary tests for original 7.1 array reader callers."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
S=ROOT/"scripts/probe-7.1-scene-point-native-caller-chain.py"
spec=importlib.util.spec_from_file_location("pointcaller71",S)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
PRIOR=ROOT/m.PRIOR_SCENE_POINT

class ScenePointNativeCallerTests(unittest.TestCase):
    def test_original_callee_identity(self):
        j=json.loads(PRIOR.read_text(encoding="utf-8"))
        n=j["sourceNativeArrayCountReader"]
        self.assertEqual(m.TARGET,0xAD23000)
        self.assertEqual(n["originalMethodRva"],f"0x{m.TARGET:X}")
        self.assertEqual(n["originalMethodIndex"],m.METHOD_INDEX)
        self.assertEqual(n["originalMethodWindowSha256"],m.SOURCE_WINDOW_SHA)
        self.assertTrue(n["genericNativeU32XorCountReaderProven"])
        self.assertFalse(n["originalScenePointLoaderCallsThisReaderProven"])

    def test_method_index_must_match_original_source(self):
        j=json.loads(PRIOR.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            csvpath=Path(tmp)/"methods.csv"
            csvpath.write_text("rva,type_name,type_definition_index,method_name,method_index,parameter_types\n"
                 "0xAD23000,NLDEPJEOJGC,63768,GMENPOPMKAA,514423,[]\n"
                 "0xAD23010,other,1,foo,3,[]\n"
                 "0xEE66B20,IJNOFJEOMBD,22426,GMENPOPMKAA,171707,[]\n",encoding="utf-8")
            with patch.object(m,"git_blob",return_value=m.METHODS_GIT_BLOB):
                starts,rows=m.validate_source(csvpath,PRIOR)
                self.assertEqual(starts[0],m.TARGET)
                self.assertEqual(rows[m.TARGET][0]["method_name"],m.METHOD)
            with patch.object(m,"git_blob",return_value="source drift"):
                with self.assertRaisesRegex(ValueError,"Git-blob mismatch"):
                    m.validate_source(csvpath,PRIOR)

    def test_wrong_source_reader_rejected(self):
        j=json.loads(PRIOR.read_text(encoding="utf-8"))
        self.assertEqual(j["originalExeSha256"],m.PROFILE_71.exe_sha256)
        self.assertEqual(j["originalMethodsGitBlob"],m.METHODS_GIT_BLOB)


    def test_original_parent_has_verified_call_site_anchor(self):
        self.assertEqual(m.PARENT_RVA,0xEE66B20)
        self.assertEqual(m.PARENT_CALL_RVA,0xEE66BF1)
        self.assertEqual(m.PARENT_TYPE,"IJNOFJEOMBD")
        self.assertEqual(m.PARENT_METHOD_INDEX,171707)
        self.assertEqual(m.FIELDS_GIT_BLOB,"ae01d117f4d884e891a95d529a15302a68715b04")


    def test_all_source_original_scene_point_prefix_masks(self):
        evidence=ROOT/m.SCENE_POINT_SOURCE_REPORT
        r=m.scene_point_mask_prefix_census(evidence)
        self.assertEqual(len(r["rows"]),13)
        self.assertTrue(r["all13HaveNativeOuterFlag8000"])
        self.assertTrue(r["all13HaveNativeOuterFlag4000"])
        self.assertTrue(r["all13HaveSameByteAtOffset2"])
        self.assertEqual({x["candidateByteAtOffset2"] for x in r["rows"]},{"0xCB"})
        self.assertEqual(r["rows"][0]["candidateOuterNativeMask"],"0xC028")
        self.assertFalse(r["originalRootParserActuallyConsumedTheseBytes"])
        self.assertFalse(r["nativeSingleBytePrecursorConsumerVerified"])


    def test_source_authenticated_parent_call_and_scene_point_mask_evidence(self):
        p=(ROOT/"versions/7.1.0-global/analyses/progression/world/"
            "7.1-original-scene-point-parent-mask-native-callchain.json")
        report=json.loads(p.read_text(encoding="utf-8"))
        self.assertEqual(report["originalExeSha256"],m.PROFILE_71.exe_sha256)
        self.assertEqual(report["originalMethodsGitBlob"],m.METHODS_GIT_BLOB)
        self.assertEqual(report["originalFieldsGitBlob"],m.FIELDS_GIT_BLOB)
        self.assertEqual(report["originalClientSource"]["archiveArtifactId"],12407956009)
        parent=report["nativeParentReader"]
        self.assertEqual(parent["owner"],m.PARENT_TYPE)
        self.assertEqual(parent["methodIndex"],m.PARENT_METHOD_INDEX)
        self.assertEqual(parent["nativeRva"],f"0x{m.PARENT_RVA:X}")
        self.assertEqual(parent["nativeSourceBytes"],864)
        self.assertEqual(parent["decodedInstructions"],203)
        self.assertEqual(parent["nativeSourceSha256"],
             "e27dc0d3a924a74963b34e8d8ff64d17ab3fe472b77dcc42b4cbe3c704a6e61a")
        self.assertEqual(len(parent["originalParentFields"]),9)
        w=parent["verifiedOriginalInstructionControls"]
        self.assertEqual(w["outerMaskTransform"]["rva"],"0xEE66B71")
        self.assertEqual(w["nestedObjectFieldPointer"]["operands"],"rax, [r14 + 0x30]")
        self.assertEqual(w["nestedObjectPresence"]["operands"],"ebx, 0x4000")
        self.assertEqual(w["nestedReaderCall"]["rva"],f"0x{m.PARENT_CALL_RVA:X}")
        helper=report["nativeIntermediateReader"]
        self.assertEqual(helper["originalOwner"],"CCPCOHEPGHC")
        self.assertEqual(helper["methodIndex"],173227)
        self.assertEqual(helper["nativeRva"],"0x12498FE0")
        self.assertEqual(helper["nativeWindowSha256"],
          "4dc0d197c153cb88a8f54e65cc7300c8fa9cefa96b1054bd3c9277feaa4cf0c2")
        byte_path=helper["verifiedInitialByteReadCursorAdvance"]
        self.assertEqual(byte_path["oneByteRead"]["rva"],"0x12499031")
        self.assertEqual(byte_path["persistAdvance"]["rva"],"0x12499039")
        self.assertFalse(helper["verifiedConsumesOnlyOneByteForOriginalByteCB"])
        mask=report["sourceOriginal13ScenePointPrefixMaskCrossCheck"]
        self.assertEqual(len(mask["perSceneRows"]),13)
        self.assertTrue(mask["all13MatchOriginalNativeFlag8000"])
        self.assertTrue(mask["all13MatchOriginalNativeFlag4000"])
        self.assertTrue(mask["all13ShareThirdByteCB"])
        direct=report["originalDirectCallCensus"]
        self.assertEqual(direct["toNestedArrayE8Candidates"],1)
        self.assertEqual(direct["toNestedArrayVerifiedAlignedCalls"],1)
        self.assertEqual(direct["fileBackedNestedReaderPointerHolderCount"],1)
        self.assertEqual(direct["toParentE8ShapedByteCandidates"],2)
        self.assertEqual(direct["toParentVerifiedAlignedCalls"],0)
        self.assertTrue(report["claims"]["originalNestedArrayReaderDirectCallerProven"])
        self.assertTrue(report["claims"]["originalParentMaskAndNestedConditionalCallProven"])
        for key in ("originalHelperConsumesExactlyOneByteForCBProven",
                    "originalScenePointAssetLoaderToParentLinkProven",
                    "originalScenePointArrayStartsAtOffset3Proven",
                    "originalScenePointRecordsDecoded",
                    "originalChestGadgetInstanceLocationsProven",
                    "originalChestLevelProven",
                    "originalServerChestInstanceAuthorityProven"):
            self.assertFalse(report["claims"][key])

if __name__=="__main__":
    unittest.main()
