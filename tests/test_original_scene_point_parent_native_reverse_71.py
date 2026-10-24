"""Global 7.1 original native scene-compatible parent reader caller regressions.

The E8 parent target false negative from an earlier study is corrected from
independent original EXE alignment, and bounded external consumer callbacks
retain their literal original method identities with no guessed Scene/Point
file path or chest placement.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
PREFIX=ROOT/"versions/7.1.0-global/analyses/progression/world"
REVERSE=PREFIX/"7.1-original-scene-point-parent-reader-reverse-native-callers.json"
CONSUMER=PREFIX/"7.1-original-point-parent-reader-kllng-consumer-native.json"
PARENT=PREFIX/"7.1-original-scene-point-parent-mask-native-callchain.json"
CALLER_SCRIPT=ROOT/"scripts/probe-7.1-point-reader-reverse-native-callers.py"
CONSUMER_SCRIPT=ROOT/"scripts/probe-7.1-scene-point-parent-native-consumer.py"
spec=importlib.util.spec_from_file_location("original_71_parent_reverse",CALLER_SCRIPT)
caller=importlib.util.module_from_spec(spec);spec.loader.exec_module(caller)
consumer_spec=importlib.util.spec_from_file_location("original_71_parent_consumer",CONSUMER_SCRIPT)
consumer=importlib.util.module_from_spec(consumer_spec);consumer_spec.loader.exec_module(consumer)


class Original71ScenePointParentNativeCallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a=json.loads(REVERSE.read_text(encoding="utf-8"))
        cls.b=json.loads(CONSUMER.read_text(encoding="utf-8"))
        cls.p=json.loads(PARENT.read_text(encoding="utf-8"))

    def test_fixed_prior_report_and_original_two_native_parent_callers(self):
        a=self.a
        self.assertEqual(a["originalExeSha256"],caller.PROFILE_71.exe_sha256)
        self.assertEqual(a["sourceMethodsGitBlob"],caller.METHODS_BLOB)
        caller.validate_prior(ROOT/caller.PRIOR_PARENT,ROOT/caller.PRIOR_FACTORY_CHAIN)
        x=a["sourceOriginalCallCensus"]["parent_candidate_scene_point_reader"]
        self.assertEqual(x["originalTargetRva"],"0xEE66B20")
        self.assertEqual(x["rawE8ShapedCandidateCount"],2)
        self.assertEqual(x["originalAlignedDeclaredMethodCallCount"],2)
        sites=x["originalCallerCandidates"]
        self.assertEqual([(x["candidateCallSiteRva"],x["sourceOriginalCallBytes"],
                           x["exactOriginalCallerStartRva"],
                           x["sourceOriginalCallerOwner"][0]["methodIndex"]) for x in sites],[
            ("0xEE67087","e894faffff","0xEE67070",171709),
            ("0xF04F4B5","e86676e1ff","0xF04F350",616020),
        ])
        self.assertTrue(all(x["aligned"] for x in sites))
        self.assertTrue(a["priorParentNativeCensusFalseNegativeCorrected"])
        self.assertTrue(self.p["originalDirectCallCensus"]["correction"]["originalRunProducedFalseNegative"])
        self.assertEqual(self.p["originalDirectCallCensus"]["toParentVerifiedAlignedCalls"],2)
        self.assertEqual(self.p["originalDirectCallCensus"]["toParentE8ShapedByteCandidates"],2)

    def test_original_reader_callee_positive_controls(self):
        c=self.a["sourceOriginalCallCensus"]
        expected={
           "intermediate_source_byte_reader":(1,1),
           "nldep_one_arg_reader":(12,12),
           "nldep_two_arg_reader":(1,1),
           "factory_case_1_owner_reader":(3,3),
           "factory_case_14_owner_reader":(0,0),
        }
        for name,(raw,aligned) in expected.items():
            with self.subTest(name=name):
                self.assertEqual(c[name]["rawE8ShapedCandidateCount"],raw)
                self.assertEqual(c[name]["originalAlignedDeclaredMethodCallCount"],aligned)
        one=c["nldep_two_arg_reader"]["originalCallerCandidates"]
        self.assertEqual(one[0]["candidateCallSiteRva"],"0xEE66BF1")

    def test_original_native_consumer_and_twelve_direct_upstream_callers(self):
        b=self.b
        consumer.verify_prior(ROOT/consumer.PRIOR)
        self.assertEqual(b["originalNativeMethodOwner"],"KLLNGCPBLMM")
        self.assertEqual(b["originalNativeMethodName"],"NPBDNMOKJPE")
        self.assertEqual(b["originalNativeMethodIndex"],616020)
        self.assertEqual(b["originalNativeMethodParameterTypes"],'["uint32"]')
        self.assertEqual(b["originalNativeMethodStartRva"],"0xF04F350")
        self.assertEqual(b["sourceNextOriginalMethodStartRva"],"0xF04F5B0")
        self.assertEqual(b["sourceOriginalMethodWindowBytes"],608)
        self.assertEqual(b["sourceOriginalMethodWindowSha256"],
           "b8e3420373fd37e3a6e563c803413206093955b27311407199682e0234219b71")
        self.assertEqual(b["sourceOriginalLinearNativeInstructions"],165)
        self.assertEqual(b["sourceOriginalE8CallersToConsumer"]["rawCandidateCount"],12)
        self.assertEqual(b["sourceOriginalE8CallersToConsumer"]["alignedOriginalNativeCallCount"],12)
        parents=b["sourceOriginalE8CallersToConsumer"]["candidates"]
        self.assertEqual(len(parents),12)
        self.assertTrue(all(x["aligned"] for x in parents))
        named=[x for x in parents if x["sourceOriginalCallerOwner"][0]["methodName"]=="IsUnderSceneHighestPoint"]
        self.assertEqual(len(named),1)
        self.assertEqual(named[0]["sourceOriginalCallerOwner"][0]["typeName"],"Miscs")
        self.assertEqual(named[0]["sourceCallRva"],"0x12E2CF1E")

    def test_no_unproven_asset_loader_or_chest_claim(self):
        self.assertFalse(self.a["sourceOriginalReaderToScenePointAssetLoaderProven"])
        self.assertFalse(self.a["sourceOriginalChestCoordinatesOrLevelProven"])
        self.assertFalse(self.b["originalScenePointPathLoaderOrFactoryVtableBindingProven"])
        self.assertFalse(self.b["originalChestPlacementOrLevelProven"])


if __name__=="__main__":unittest.main()
