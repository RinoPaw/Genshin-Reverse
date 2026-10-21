"""Regression for source-bound Gadget auxiliary wrapped-key candidate screening."""
from pathlib import Path
import json
import unittest
from genshinre.nativeprofile import PROFILE_71

PATH=Path(__file__).resolve().parents[1]/"versions/7.1.0-global/analyses/progression/economy/7.1-gadget-aux-native-row-reader-candidates.json"


class NativeGadgetAuxReaderEvidenceTests(unittest.TestCase):
    def test_exact_client_conclusions_have_no_promoted_semantics(self):
        data=json.loads(PATH.read_text(encoding="utf-8"))
        self.assertEqual(data["source"]["exeSha256"],PROFILE_71.exe_sha256)
        self.assertEqual(data["source"]["nativeDirectWrapperCallSites"],11833)
        self.assertEqual(data["source"]["nativeMatchingReaderSignatureCalls"],10346)
        self.assertEqual(data["source"]["originalFullCandidatesArtifactId"],12356062950)
        self.assertEqual(len(data["source"]["fullCandidateJsonSha256"]),64)
        self.assertEqual(
            {name:item["matchedWrappedKeyWriterMethodCandidates"]
             for name,item in data["tables"].items()},
            {"GadgetPropExcelConfigData":542,"GadgetInteractExcelConfigData":485})
        for item in data["tables"].values():
            self.assertEqual(len(item["originalRowClassStaticRipRefs"]),2)
            self.assertEqual(item["within50ManagerTypeIndices"],1)
            self.assertFalse(item["closestCandidate"]["identifiedAsActualVtableRowReader"])

    def test_witness_addresses_and_distinct_memory_keys(self):
        data=json.loads(PATH.read_text(encoding="utf-8"))["tables"]
        self.assertEqual(data["GadgetPropExcelConfigData"]["closestCandidate"]["methodIndex"],225165)
        self.assertEqual(data["GadgetInteractExcelConfigData"]["closestCandidate"]["methodIndex"],219773)
        self.assertEqual(data["GadgetPropExcelConfigData"]["verifiedManager"]["preGetterRowKeyOffset"],"0x1C")
        self.assertEqual(data["GadgetInteractExcelConfigData"]["verifiedManager"]["preGetterRowKeyOffset"],"0x28")


if __name__=="__main__":
    unittest.main()
