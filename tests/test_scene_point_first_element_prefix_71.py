"""Original 7.1 Scene Point source-prefix byte-gate tests."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts/probe-7.1-scene-point-first-element-prefix.py"
spec=importlib.util.spec_from_file_location("source_point_element_71",SCRIPT)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class SourceScenePointElementPrefixGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows,cls.factory=m.evidence_samples(ROOT/m.ORIGINAL_SAMPLES,ROOT/m.ORIGINAL_FACTORY)

    def test_exact13_original_scene_headers_and_factory_source_identity(self):
        self.assertEqual(len(self.rows),13)
        self.assertEqual(self.factory["originalExeSha256"],m.EXE_SHA)
        self.assertEqual(self.factory["originalArrayNativeReader"]["countReadXorConstant"],"0xC14B813C")
        self.assertEqual(self.factory["originalFactory"]["exactAlignedNativeJumpCaseCount"],31)

    def test_original_all_source_prefix_candidates(self):
        r=m.prefix_candidates(self.rows)
        self.assertEqual(r["candidateArraysLengthsFromOriginal13SourcePrefixes"],
                         [1727,28,28,20,14,60,19,24,18,25,56,26,1])
        self.assertTrue(r["offset7AllThirteenFailOriginalSubtypeFactory"])
        self.assertEqual(r["soleAll13SourcePassingByteOffset"],10)
        self.assertEqual([x["nativeTransformedNumericSubtypeCandidate"] for x in r["sourceSubtypeAtOffset10Candidate"]],
                         [14,1,1,1,17,1,1,1,1,1,1,1,1])
        self.assertEqual(len(r["all32SourceOffsetsDiscriminatorCensus"]),32)
        self.assertEqual(r["sourceCandidatePreludeLengths"],[1,1,1,1,2,1,1,1,1,1,1,1,1])
        self.assertEqual(r["sourceCandidateFirstElementByteOffsets"],[10,10,10,10,11,10,10,10,10,10,10,10,10])
        self.assertEqual([x["candidateOriginalFactoryTypeId"] for x in r["sourceDynamicFirstElementSubtypeCandidates"]],
                         [14,1,1,1,1,1,1,1,1,1,1,1,1])
        self.assertTrue(r["all13NativeLengthAdjustedSubtypeCandidatesValid"])
        self.assertFalse(r["nativeCursorConsumptionForExtraThreeBytesProven"])
        self.assertFalse(r["sourceAssetLoaderToOriginalNativeArrayReaderProven"])
        self.assertFalse(r["actualFirstElementDiscriminatorOffsetProven"])

    def test_native_factory_byte_formula(self):
        self.assertEqual(m.decode_native_kind(0x2f),14)
        self.assertEqual(m.decode_native_kind(0x38),1)
        self.assertEqual(m.decode_native_kind(0x28),17)
        self.assertEqual(m.decode_native_kind(0x67),198)

    def test_drift_rejected(self):
        rows=[dict(x) for x in self.rows]
        rows[0]["unwrappedPayloadFirst32Hex"]="00"*32
        with self.assertRaisesRegex(ValueError,"original source byte-2 helper input changed"):
            m.prefix_candidates(rows)


    def test_original_native_length_aware_prefix_evidence(self):
        file=(ROOT/"versions/7.1.0-global/analyses/progression/world/"
              "7.1-original-scene-point-first-element-native-length-prefix.json")
        j=json.loads(file.read_text(encoding="utf-8"))
        self.assertEqual(j["originalExeSha256"],m.PROFILE_71.exe_sha256)
        self.assertEqual(j["originalMethodsGitBlob"],m.METHODS_BLOB)
        self.assertEqual(j["sourceArtifactId"],12410568240)
        reader=j["originalNativeArrayReader"]
        self.assertEqual(reader["nativeSha256"],m.RVA_SHA)
        self.assertEqual(reader["nativeInstructionCount"],392)
        anchors=reader["sourceInstructionAnchors"]
        self.assertEqual(anchors["0xAD23124"]["operands"],
                         "r12d, word ptr [rax + rdx + 0x20]")
        self.assertEqual(anchors["0xAD23132"]["operands"],"r12w, ax")
        self.assertEqual(anchors["0xAD23320"]["operands"],"0x14fd53090")
        self.assertEqual(anchors["0xAD23393"]["operands"],
                         "eax, byte ptr [rax + rdx + 0x20]")
        helper=j["independentlyAuthenticatedOriginalCursorAdvanceHelper"]
        self.assertEqual(helper["originalCursorIncrementRva"],"0xFD53179")
        self.assertEqual(helper["nativeCallInThisArrayReader"],"0xAD23320")
        decoded=j["observed13OriginalScenePointPrefixCandidateDecode"]
        self.assertEqual(decoded["dynamicLengthOneSampleCount"],12)
        self.assertEqual(decoded["dynamicLengthTwoSampleCount"],1)
        self.assertEqual([x["candidateFirstElementByteOffset"]
                          for x in decoded["originalSamples"]],
                         [10,10,10,10,11,10,10,10,10,10,10,10,10])
        self.assertEqual([x["sourceOriginalFactoryNumericTypeCandidate"]
                          for x in decoded["originalSamples"]],
                         [14,1,1,1,1,1,1,1,1,1,1,1,1])
        self.assertTrue(decoded["all13DynamicSubtypeCandidatesWithinFactoryCase0To30"])
        self.assertTrue(decoded["immediateAfterArrayCountAtByte7All13InvalidFactory"])
        self.assertFalse(j["unresolved"]["sourceScenePointResourceIsInputOfNamedOriginalNativeReader"])
        self.assertFalse(j["unresolved"]["scenePointPositionsDecoded"])
        self.assertFalse(j["unresolved"]["chestGadgetInstancePlacementDecoded"])

if __name__=="__main__":
    unittest.main()
