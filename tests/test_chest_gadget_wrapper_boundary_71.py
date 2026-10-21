"""Evidence and scope guards for exact 7.1 Gadget wrapper global address search."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
REPORT = (ROOT / "versions/7.1.0-global/analyses/progression/economy"
          / "7.1-chest-native-gadget-wrapper-global-boundary.json")


class TestGadgetWrapperGlobalEvidence71(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(REPORT.read_text(encoding="utf-8"))

    def test_original_client_rip_targets_match_both_functions(self):
        # RVA + instruction length + signed RIP displacement.
        self.assertEqual(0xBB16026 + 7 - 0x6392E45, 0x57831E8)
        self.assertEqual(0xBB15F56 + 7 - 0x6392D75, 0x57831E8)
        self.assertEqual(0xBB160A3 + 6 - 0x638AFA9, 0x578B100)
        self.assertEqual(0xBB15F6D + 6 - 0x638AE73, 0x578B100)
        obj = self.report["staticGlobals"]
        self.assertEqual(obj["ownerPointer"]["rva"], "0x57831E8")
        self.assertEqual(obj["xorWord"]["rva"], "0x578B100")

    def test_static_absence_does_not_become_runtime_conclusion(self):
        r = self.report
        self.assertEqual(r["source"]["exeSha256"],
                         "08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d")
        self.assertEqual(r["staticGlobals"]["ownerPointer"]["reportedFileBackedBytesHex"], "")
        self.assertEqual(r["staticGlobals"]["xorWord"]["reportedFileBackedBytesHex"], "")
        self.assertGreater(r["staticGlobals"]["ownerPointer"]
                           ["recognizedMovLeaReadCandidates"], 1000000)
        self.assertGreater(r["staticGlobals"]["xorWord"]
                           ["recognizedMovLeaReadCandidates"], 100)
        self.assertEqual(r["staticGlobals"]["xorWord"]
                         ["recognizedMovLeaWriteCandidates"], 0)
        proof = r["nextProof"]
        self.assertEqual(proof["runtimeArrayBytes"], 2048)
        self.assertFalse(proof["actualTableBytesCaptured"])
        self.assertFalse(proof["roundTripVerified"])
        self.assertEqual(proof["serverChestRewardAuthenticity"], "UNRESOLVED")
        self.assertTrue(any("MOV/LEA" in x for x in r["limitations"]))
        self.assertTrue(any("runtime" in x for x in r["limitations"]))


if __name__ == "__main__":
    unittest.main()
