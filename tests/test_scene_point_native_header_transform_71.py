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
        self.assertEqual({x["headerOffset"] for x in leads},{3})
        self.assertEqual({x["operation"] for x in leads},{"xor"})
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

if __name__=="__main__":
    unittest.main()
