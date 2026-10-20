"""Source-pinned synthetic checks for 7.1 Gadget row presence-mask evidence."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/probe-7.1-gadget-presence-bits.py"
spec = importlib.util.spec_from_file_location("gadget_presence_71", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class TestGadgetPresenceBits71(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.layout = json.loads(probe.LAYOUT.read_text(encoding="utf-8"))
        cls.reader = json.loads(probe.READER.read_text(encoding="utf-8"))
        cls.expected = json.loads(probe.OUTPUT.read_text(encoding="utf-8"))

    def synthetic_trace(self):
        rows = [
            {"rva": f"0x{rva:X}", "mnemonic": mnemonic, "op_str": operands}
            for rva, mnemonic, operands in probe.MASK_STEPS
        ]
        for item in self.expected["fieldsInNativeReadOrder"]:
            rows.extend([
                {"rva": item["testRva"], "mnemonic": "test",
                 "op_str": item["testOperands"]},
                {"rva": item["branchRva"], "mnemonic": item["branchMnemonic"].lower(),
                 "op_str": item["branchTarget"]},
            ])
        rows.sort(key=lambda row: int(row["rva"], 16))
        return {
            "exe_sha256": self.reader["source"]["exeSha256"],
            "start_rva": self.reader["source"]["methodRva"],
            "instruction_count": self.reader["disassembly"]["decodedInstructions"],
            "instructions": rows,
        }

    def test_all_22_guards_and_expected_snapshot(self):
        result = probe.correlate(self.synthetic_trace(), self.layout, self.reader,
                                 digest=self.reader["source"]["disassemblyJsonSha256"])
        self.assertEqual(result, self.expected)
        self.assertEqual(len(set(x["maskBit"] for x in result["fieldsInNativeReadOrder"])), 22)
        self.assertEqual(result["mask"]["decodeConstant"], "0x00000000466DB4EB")

    def test_changed_mask_constant_rejected(self):
        trace = self.synthetic_trace()
        next(x for x in trace["instructions"] if x["rva"] == "0x10278EC1")[
            "op_str"] = "edi, 0x466db4ec"
        with self.assertRaisesRegex(ValueError, "mask construction"):
            probe.correlate(trace, self.layout, self.reader,
                            digest=self.reader["source"]["disassemblyJsonSha256"])

    def test_changed_guard_and_source_rejected(self):
        trace = self.synthetic_trace()
        next(x for x in trace["instructions"] if x["rva"] == "0x10278ED1")[
            "op_str"] = "edi, 0x10000"
        with self.assertRaisesRegex(ValueError, "presence bit mismatch"):
            probe.correlate(trace, self.layout, self.reader,
                            digest=self.reader["source"]["disassemblyJsonSha256"])
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            probe.correlate(self.synthetic_trace(), self.layout, self.reader,
                            digest="0" * 64)

    def test_layout_perturbation_rejected(self):
        changed = copy.deepcopy(self.layout)
        changed["result"]["mapping"][0]["candidateInstanceOffset"] = "0x44"
        with self.assertRaisesRegex(ValueError, "missing, duplicated or foreign"):
            probe.correlate(self.synthetic_trace(), changed, self.reader,
                            digest=self.reader["source"]["disassemblyJsonSha256"])


if __name__ == "__main__":
    unittest.main()
