"""Immutable evidence contract for pinned Global 7.1 Amber pre-mask direct-call analysis.

This test validates committed research findings, not gameplay or Frida attachment.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = (ROOT / "versions/7.1.0-global/windows-x64/analyses/"
            "amber-pause-ack/posttalk-native-guide-call-edges.json")
EXPECTED_SAMPLE = "08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d"


class AmberPreMaskDirectEdgesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    def test_evidence_bound_to_exact_sample(self):
        self.assertEqual(self.data["sample"]["exe_sha256"], EXPECTED_SAMPLE)
        self.assertIn("RUNTIME_CAUSE_UNRESOLVED", self.data["status"])

    def test_guide_entry_is_a_lua_wrapper_candidate(self):
        guide = next(e for e in self.data["direct_edges"]
                     if e["target"] == "GlobalActor.StartGuide(string)")
        self.assertEqual(guide["validated_direct_e8_callers"], 1)
        self.assertEqual(guide["caller"]["method"], "MoleMoleGlobalActorWrap._m_StartGuide(native_int)")
        self.assertEqual(guide["caller"]["call_site"], "0xC70CCF5")

    def test_guide_visibility_and_input_lock_are_separate_unverified_paths(self):
        edges = {e["target"]: e for e in self.data["direct_edges"]}
        self.assertEqual(edges["InteractionManager.LockInter(ELockReason)"]
                         ["validated_direct_e8_callers"], 0)
        self.assertEqual(edges["InteractionManager.UnLockInter(ELockReason)"]
                         ["validated_direct_e8_callers"], 3)
        self.assertEqual(edges["MonoNewbieDialog.SetNewbieMaskIndex(int32)"]
                         ["validated_direct_e8_callers"], 4)
        self.assertEqual(edges["InteractionManager.UnLockInter(ELockReason)"]
                         ["enum_name_for_1"], "UNCONFIRMED")
        self.assertGreaterEqual(len(self.data["limits"]), 3)

    def test_cmd2178_does_not_claim_guide_identity(self):
        self.assertEqual(self.data["cmd2178"]["protobuf_field"], 15)
        self.assertEqual(self.data["cmd2178"]["guide_semantics"], "UNRESOLVED")


if __name__ == "__main__":
    unittest.main()
