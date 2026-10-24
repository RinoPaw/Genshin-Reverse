"""Original Global 7.1 Scene/Point executable lookup literal regression.

Checks exact 13 scene file identities, original native reader controls,
section-scoped negative literal outcomes and the one 4-byte incidental
candidate. The source binary is not downloaded by ordinary CI.
"""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts/probe-7.1-scene-point-native-lookup-literals.py"
REPORT=ROOT/"versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-client-lookup-literals.json"
spec=importlib.util.spec_from_file_location("original_71_point_native_lookups",SCRIPT)
probe=importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class Original71ScenePointLookupLiterals(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d=json.loads(REPORT.read_text(encoding="utf-8"))

    def test_source_original_asset_path_hash_positive_controls(self):
        d=self.d
        self.assertEqual(d["originalExeSha256"],probe.PROFILE_71.exe_sha256)
        self.assertEqual(d["sourceDesignIndexSha256"],probe.ORIGINAL_DESIGN_INDEX_SHA)
        assets=probe.validate_source(ROOT/probe.ORIGINAL_SCENES,ROOT/probe.ORIGINAL_READER)
        self.assertEqual([x["sceneId"] for x in assets],list(probe.ORIGINAL_SCENE_IDS))
        self.assertEqual([x["sceneId"] for x in d["sceneRows"]],list(probe.ORIGINAL_SCENE_IDS))
        for original,record in zip(assets,d["sceneRows"],strict=True):
            with self.subTest(scene=record["sceneId"]):
                self.assertEqual(record["originalPath"],original["candidateOriginalPath"])
                self.assertEqual(record["exactOriginalIndexNameHash"],original["namePathHash"])
                self.assertFalse(record["originalScenePointAssetLoaderMethodResolved"])

    def test_all_source_full_hash_and_path_literals_absent(self):
        d=self.d
        sections=d["originalExecutableSectionsExamined"]
        self.assertEqual(len(sections),13)
        self.assertEqual(sum(x["sourceBytes"] for x in sections),444246016)
        no_matches=(
          "nameHash40LittleEndian5","nameHashZeroExtendedQword8",
          "exactPathAscii","exactPathUTF16LE",
          "exactFilenameAscii","exactFilenameUTF16LE"
        )
        for record in d["sceneRows"]:
            with self.subTest(scene=record["sceneId"]):
                counts=record["literalHitCountByForm"]
                for form in no_matches:self.assertEqual(counts[form],0)
                self.assertEqual(sum(counts.values())-counts["nameHashLow32LittleEndian4"],0)
        self.assertEqual({k:len(v) for k,v in d["sharedPathSubstringLiteralMatches"].items()},
                         {"sharedPointPathPrefixAscii":0,"sharedPointPathPrefixUTF16LE":0})

    def test_only_incidental_four_byte_candidate_is_non_code_section(self):
        rows=self.d["sceneRows"]
        sample=[x for x in rows if x["sceneId"]==101][0]
        matching=sample["sourceOriginalLiteralMatches"]["nameHashLow32LittleEndian4"]
        self.assertEqual(matching,[{
          "rva":"0x67FB5E4","section":".pdata","executableSection":False,
          "needleHex":"1b7f05d2","surroundingHex":"c87e77ab662255f61b7f05d2019e7d2de06ffa26"
        }])
        self.assertEqual(sum(x["literalHitCountByForm"]["nameHashLow32LittleEndian4"] for x in rows),1)
        self.assertTrue(all(not x["sourceOriginalLiteralMatches"]["nameHash40LittleEndian5"] for x in rows))
        self.assertEqual(self.d["sourceOriginalRunHeadSha"],"a811660829f8e7ecb2ec8d25ad470278487a68b9")
        self.assertTrue(self.d["sourceOriginalArtifactDigest"].startswith("sha256:"))

    def test_no_semantic_claims_from_raw_bytes(self):
        for name in ("originalResourcePathHashToRuntimeLookupLinkProven",
                     "originalScenePointLoaderToNativeReaderLinkProven",
                     "originalChestGadgetPositionsOrLevelProven"):
            self.assertFalse(self.d[name])
        test=b"ABCDE00ABCDDDABCD"
        m=probe.find_hits(test,b"ABCD",0x1000,".text",executable=True)
        self.assertEqual([x["rva"] for x in m],["0x1000","0x1007","0x100D"])
        self.assertTrue(all(x["executableSection"] for x in m))
        self.assertEqual(probe.find_hits(test,b"ABCG",0x1000,".text",executable=True),[])


if __name__=="__main__":
    unittest.main()
