"""Synthetic regression checks for the exact 7.1 Gadget bool wire probe."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/probe-7.1-gadget-bool-wire.py"
spec = importlib.util.spec_from_file_location("gadget_bool_wire_71", SCRIPT)
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)


class TestGadgetBoolWire71(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.layout = json.loads(wire.LAYOUT.read_text(encoding="utf-8"))
        cls.reader = json.loads(wire.READER.read_text(encoding="utf-8"))
        cls.expected = json.loads(wire.OUTPUT.read_text(encoding="utf-8"))

    def synthetic_disassembly(self):
        instructions = []
        for record in self.expected["byteFields"]:
            branch = record["decodedByteBranches"][0]
            output_register = "cl" if branch["inputRegister"] == "dl" else "al"
            for _ in range(9):
                instructions.append({"rva": "0x0", "mnemonic": "nop", "op_str": ""})
            instructions.extend([
                {"rva": branch["comparisonRva"], "mnemonic": "cmp",
                 "op_str": f'{branch["inputRegister"]}, {branch["encodedFalseByte"].lower()}'},
                {"rva": branch["predicateRva"], "mnemonic": "setne",
                 "op_str": output_register},
                {"rva": branch["storeRva"], "mnemonic": "mov",
                 "op_str": f'byte ptr [r14 + {record["candidateMemoryOffset"].lower()}], {output_register}'},
            ])
        for record in self.expected["byteFields"]:
            if not record["zeroStores"]:
                continue
            for _ in range(9):
                instructions.append({"rva": "0x0", "mnemonic": "nop", "op_str": ""})
            for rva in record["zeroStores"]:
                instructions.extend([
                    {"rva": "0x0", "mnemonic": "xor", "op_str": "ecx, ecx"},
                    {"rva": rva, "mnemonic": "mov",
                     "op_str": f'byte ptr [r14 + {record["candidateMemoryOffset"].lower()}], cl'},
                ])
        return {
            "exe_sha256": self.reader["source"]["exeSha256"],
            "start_rva": self.reader["source"]["methodRva"],
            "instruction_count": self.reader["disassembly"]["decodedInstructions"],
            "instructions": instructions,
        }

    def test_all_eight_native_comparisons(self):
        report = wire.inspect(self.synthetic_disassembly(), self.layout, self.reader,
                              source_sha256=self.reader["source"]["disassemblyJsonSha256"])
        self.assertEqual(report, self.expected)
        self.assertEqual(len(report["byteFields"]), 8)
        self.assertEqual(sum(len(f["zeroStores"]) for f in report["byteFields"]), 2)

    def test_missing_instruction_or_unrelated_sample_rejected(self):
        altered = self.synthetic_disassembly()
        altered["instructions"] = [ins for ins in altered["instructions"]
                                   if ins["rva"] != "0x10279627"]
        with self.assertRaisesRegex(ValueError, "unclassified|missing or ambiguous"):
            wire.inspect(altered, self.layout, self.reader,
                         source_sha256=self.reader["source"]["disassemblyJsonSha256"])
        altered = self.synthetic_disassembly()
        altered["exe_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "source identity"):
            wire.inspect(altered, self.layout, self.reader,
                         source_sha256=self.reader["source"]["disassemblyJsonSha256"])


if __name__ == "__main__":
    unittest.main()
