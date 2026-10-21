"""Exact-source synthetic regression tests for 7.1 Gadget scalar wrapper trace."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/probe-7.1-gadget-key-wrapper.py"
spec = importlib.util.spec_from_file_location("gadget_key_helper_71", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class TestGadgetNativeKeyWrapper71(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(probe.REPORT.read_text(encoding="utf-8"))

    def fake_inputs(self):
        samples = {}
        digests = {}
        for label, (rva, sha) in probe.SOURCES.items():
            samples[label] = {
                "exe_sha256": self.report["exeSha256"],
                "start_rva": rva,
                "instructions": [
                    {"rva": at, "mnemonic": mnemonic, "op_str": operands}
                    for at, mnemonic, operands in probe.ANCHORS[label]
                ],
            }
            digests[label] = sha
        return samples, digests

    def test_pinned_native_u32_writer_getter_evidence(self):
        samples, digests = self.fake_inputs()
        self.assertEqual(probe.inspect(samples, digests), self.report)
        relationship = self.report["nativeRelationship"]
        self.assertEqual(relationship["writeWrapperRva"], "0xBB16020")
        self.assertEqual(relationship["readWrapperRva"], "0xBB15F50")
        self.assertEqual(relationship["preWrapperScalarOffsets"], ["0x18", "0x30"])
        self.assertEqual(relationship["runtimeLookupTableValues"], "UNRESOLVED")
        self.assertEqual(relationship["roundTripEquivalence"], "UNVERIFIED")

    def test_wrong_sample_or_modified_native_instruction_fail_closed(self):
        samples, digests = self.fake_inputs()
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            probe.inspect(samples, {**digests, "wrapper": "0"*64})
        changed = copy.deepcopy(samples)
        changed["inherited"]["instructions"][0]["op_str"] = "esi, 0x5487"
        with self.assertRaisesRegex(ValueError, "instruction mismatch"):
            probe.inspect(changed, digests)
        changed = copy.deepcopy(samples)
        changed["loader"]["exe_sha256"] = "0"*64
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            probe.inspect(changed, digests)

    def test_source_anchors_require_both_read_and_write(self):
        samples, digests = self.fake_inputs()
        changed = copy.deepcopy(samples)
        changed["getter"]["instructions"] = changed["getter"]["instructions"][:-1]
        with self.assertRaisesRegex(ValueError, "instruction mismatch"):
            probe.inspect(changed, digests)


if __name__ == "__main__":
    unittest.main()
