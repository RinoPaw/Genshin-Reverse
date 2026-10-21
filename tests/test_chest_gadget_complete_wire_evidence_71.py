"""Pin exact 7.1 Gadget native reader chain identities and transforms."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

from genshinre import gadgetbin

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "versions/7.1.0-global/analyses/progression/economy/7.1-chest-native-gadget-complete-wire-evidence.json"


class TestGadgetCompleteWireEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(FILE.read_text(encoding="utf-8"))

    def test_native_chain_and_header_count(self):
        result = self.report
        self.assertEqual(result["source"]["sample"] if "sample" in result["source"] else result["source"]["target"],
                         "7.1.0-global/windows-x64")
        methods = result["methodChain"]
        self.assertEqual([(m["methodIndex"], m["rva"]) for m in methods],
                         [(197827, "0x968F690"), (197826, "0x968F160"),
                          (483590, "0x10278E50"), (395933, "0xBD56F60")])
        self.assertTrue(all(len(m["disassemblySha256"]) == 64 for m in methods))
        hdr = result["wire"]["header"]
        self.assertEqual(int(hdr["add"], 16), gadgetbin.HEADER_COUNT_ADD)
        self.assertEqual((int(hdr["raw"], 16) + gadgetbin.HEADER_COUNT_ADD) & 0xFFFFFFFF,
                         hdr["decodedCount"])
        self.assertEqual(hdr["decodedCount"], 30599)
        self.assertEqual(result["reproduction"]["unreadBytes"], 0)

    def test_every_native_inherited_field_matches_decoder(self):
        wire = self.report["wire"]["inherited"]
        self.assertEqual(int(wire["maskDecodeAdd"], 16), gadgetbin.BASE_MASK_ADD)
        self.assertEqual(len(wire["fieldsInNativeReadOrder"]), len(gadgetbin.BASE_SCHEMA))
        self.assertEqual(
            [(int(row["flag"], 16), int(row["offset"], 16)) for row in wire["fieldsInNativeReadOrder"]],
            [(flag, offset) for flag, offset, _, _ in gadgetbin.BASE_SCHEMA])
        self.assertEqual(int(wire["fieldsInNativeReadOrder"][3]["stringChunkXor"], 16),
                         gadgetbin.BASE_STRING_KEY)
        self.assertEqual(int(self.report["wire"]["inner"]["nativePresenceMaskDecodeAdd"], 16),
                         gadgetbin.MASK_ADD)
        self.assertEqual(len(gadgetbin.SCHEMA), 22)
        self.assertIn("+0x5473", " ".join(self.report["limits"]))


if __name__ == "__main__":
    unittest.main()
