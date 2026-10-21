"""Bounded original Global 7.1 SceneTag/SceneExcel row key-writer candidate evidence."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

from genshinre.nativeprofile import PROFILE_71

ROOT = Path(__file__).resolve().parents[1]
REPORT = (ROOT / "versions/7.1.0-global/analyses/progression/economy"
          / "7.1-chest-scene-native-keywriter-candidate-scope.json")


class TestNativeSceneKeywriterCandidateScope71(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(REPORT.read_text(encoding="utf-8"))

    def test_original_exe_and_method_identity(self):
        r = self.report
        self.assertEqual(r["source"]["exeSha256"], PROFILE_71.exe_sha256)
        self.assertEqual(r["source"]["methodsGitBlob"],
                         "a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a")
        self.assertEqual(r["source"]["fullCandidateReportSha256"],
                         "5a545acb63f01af15dfe2793307c14f9e71a548a829b4e190c62d8a4a6be2169")
        self.assertEqual(r["nativeFilter"]["wrappedU32WriterRva"], "0xBB16020")
        self.assertEqual(r["nativeFilter"]["knownInheritedGadgetWrapperCalls"], 2)

    def test_filter_counts_are_native_candidates_not_verified_row_types(self):
        r = self.report
        v = r["nativeFilter"]
        self.assertEqual(v["directWrapperCallSites"], 11833)
        self.assertEqual(v["sameNameAndInputTypeCallSites"], 10346)
        self.assertEqual(v["distinctSameSignatureMethodCandidates"], 3094)
        self.assertEqual(v["methodsWithNativeWrappedKeyStore0x28"], 485)
        self.assertEqual(v["methodsWithNativeWrappedKeyStore0x50"], 168)
        self.assertEqual(r["tables"]["SceneTag"]["rowMemoryKeyOffset"], "0x28")
        self.assertEqual(r["tables"]["SceneExcel"]["rowMemoryKeyOffset"], "0x50")
        self.assertEqual(r["tables"]["SceneExcel"]["within50MetadataTypeIndices"], 0)
        self.assertFalse(r["verifiedVsUnknown"]["objectRuntimeVirtualRowReaderResolved"])
        self.assertFalse(r["verifiedVsUnknown"]["sourceRowEndToEndParsed"])
        self.assertFalse(r["verifiedVsUnknown"]["originalSceneInstanceAndServerDropTagProven"])
        self.assertEqual(r["tables"]["SceneTag"]["matches"], 485)
        self.assertEqual(r["tables"]["SceneExcel"]["matches"], 168)
        self.assertEqual(r["nativeFilter"]["knownInheritedGadgetPositiveControlMethodIndex"], 395933)
        self.assertTrue(any("not verified" in item.lower()
                            for item in r["limitations"]))


if __name__ == "__main__":
    unittest.main()
