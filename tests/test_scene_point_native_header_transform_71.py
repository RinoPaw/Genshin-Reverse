"""Original source-bounded Scene/Point count-immediate hypotheses remain unproven."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts/probe-7.1-scene-point-native-header-transform.py"
spec=importlib.util.spec_from_file_location("pointheader71",SCRIPT)
p=importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
PRIOR=ROOT/p.PRIOR_REPORT

class OriginalScenePointHeaderTransformTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prior=json.loads(PRIOR.read_text(encoding="utf-8"))
        cls.rows=p.validate_prior(cls.prior)

    def test_source_pinned_all_thirteen_exact_client_assets(self):
        self.assertEqual([x["sceneId"] for x in self.rows],
                         [3,4,5,6,7,9,10,11,100,101,102,103,51195])
        self.assertEqual(self.rows[0]["rawExportSha256"],p.RAW_SCENE3)
        self.assertEqual(self.prior["exactOriginalExeSha256"],p.PROFILE_71.exe_sha256)

    def test_reject_source_identity_drift(self):
        spoof=json.loads(json.dumps(self.prior))
        spoof["source"]["exactBranchCommit"]="fake"
        with self.assertRaisesRegex(ValueError,"source-original"):
            p.validate_prior(spoof)

    def test_native_count_leads_are_only_byte_size_candidates(self):
        leads=p.candidate_transforms(self.rows)
        self.assertTrue(leads)
        # The 13 source-extracted Point prefixes are jointly restrictive:
        # only byte offset 3 with XOR survives the two-byte minimum bound.
        self.assertTrue(any(x["headerOffset"]==3 and x["operation"]=="xor" for x in leads))
        for x in leads:
            self.assertFalse(x["nativeCountTransformProven"])
            self.assertEqual(len(x["candidateCountsIfTransform"]),13)
            self.assertTrue(all(count*2 <= r["payloadBytes"]
                                for count,r in zip(x["candidateCountsIfTransform"],
                                                   self.rows,strict=True)))

    def test_minimal_fake_header_has_no_source_proven_semantics(self):
        fake=[{"payloadBytes":100,
               "unwrappedPayloadFirst32Hex":("00"*3+"00000000"+"00"*25)}]*13
        for candidate in p.candidate_transforms(fake):
            self.assertFalse(candidate["nativeCountTransformProven"])


    def test_exact_original_native_array_count_evidence(self):
        path=(ROOT/"versions/7.1.0-global/analyses/progression/world/"
                   "7.1-original-scene-point-native-xor-reader-evidence.json")
        j=json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(j["originalExeSha256"],p.PROFILE_71.exe_sha256)
        self.assertEqual(j["originalMethodsGitBlob"],p.METHOD_BLOB)
        self.assertEqual(j["archivedRunArtifactId"],12406477477)
        self.assertEqual(j["mathematicalCandidateCount"],44)
        self.assertEqual(j["mathematicallyViableCandidateGroups"],
                         {"3_xor":22,"6_add":22})
        self.assertEqual(j["nativeOriginalExecutableMatchedKeys"],["0xC14B813C"])
        self.assertEqual(j["nativeOriginalExecutableAlignedImmediateMatches"],1)
        native=j["sourceNativeArrayCountReader"]
        self.assertEqual(native["originalTypeName"],"NLDEPJEOJGC")
        self.assertEqual(native["originalMethodIndex"],514423)
        self.assertEqual(native["originalMethodRva"],"0xAD23000")
        self.assertEqual(native["originalMethodWindowBytes"],1568)
        self.assertEqual(native["originalMethodWindowSha256"],
                         "6319613278adf382bf7ce513d1d875ef98b318d5f5f3bc9c423b72caebd7c0ad")
        self.assertTrue(native["sourceMethodFullyDisassembled"])
        self.assertEqual(native["decodedNativeInstructions"],392)
        self.assertEqual(native["sourceAlignedImmediateInstruction"]["bytes"],"bb3c814bc1")
        self.assertEqual([x["rva"] for x in native["verifiedReadAndLoopInstructions"]],
                         ["0xAD23053","0xAD23060","0xAD23063","0xAD2306B",
                          "0xAD2306F","0xAD23072","0xAD230BB","0xAD230CC"])
        self.assertTrue(native["genericNativeU32XorCountReaderProven"])
        self.assertEqual(native["crossSceneCandidateCountsForPrefixOffset3"],
                         [1727,28,28,20,14,60,19,24,18,25,56,26,1])
        for x in ("sourceOriginalScenePointStreamStartsAtHypothesizedOffsetProven",
                  "originalScenePointLoaderCallsThisReaderProven",
                  "originalPointRowDecoderProven","fullOriginalScenePointByteConsumptionProven"):
            self.assertFalse(native[x])
        self.assertFalse(j["originalChestGadgetInstancePlacementProven"])
        self.assertFalse(j["originalServerChestPlacementOwnershipProven"])

if __name__=="__main__":
    unittest.main()
