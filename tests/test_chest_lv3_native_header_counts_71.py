"""Bound the exact 7.1 audio/handbook count-immediate native scan."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
script = ROOT / "scripts/probe-7.1-chest-lv3-native-header-counts.py"
spec = importlib.util.spec_from_file_location("native_chest_lv3_header", script)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ChestLv3NativeHeaderTests(unittest.TestCase):
    def test_one_step_arithmetic_is_not_a_native_count_proof(self):
        self.assertEqual(mod.candidate_constants(0x81F9C7B9, 56), {
            "add": 0x7E06387F,
            "sub": 0x81F9C781,
            "xor": 0x81F9C781,
        })
        self.assertEqual(mod.candidate_constants(0x6F0ECC2E, 252), {
            "add": 0x90F134CE,
            "sub": 0x6F0ECB32,
            "xor": 0x6F0ECCD2,
        })
        with self.assertRaisesRegex(ValueError, "invalid source header"):
            mod.candidate_constants(0, 0)

    def test_scanner_requires_real_gadget_positive(self):
        src = {key: {
            "hypotheticalNativeArithmeticConstants": {
                op: f"0x{word:08X}" for op, word in
                mod.candidate_constants(int(header, 16), count).items()
            },
            "hypotheticalCommunityRowCount": count
        } for key, (header, count) in {
            "audioChestType": ("81F9C7B9", 56),
            "handbookOpenChest": ("6F0ECC2E", 252)
        }.items()}
        gadget = bytes.fromhex(mod.GADGET_POSITIVE_SIGNATURE)
        synthetic = [
            (mod.GADGET_POSITIVE_RVA, gadget),
            (0x1000, bytes.fromhex("bf7f38067e037c0820") +
             bytes.fromhex("bad2cc0e6f") + bytes.fromhex("b8d2cc0e6f33440820"))
        ]
        report = mod.inspect_sections(synthetic, src)
        self.assertEqual(report["gadgetPositiveLoaderSignature"],
                         f"0x{mod.GADGET_POSITIVE_RVA:X}")
        self.assertTrue(report["tables"]["audioChestType"]["literalImmediateHits"] > 0)
        self.assertTrue(any(x["operator"] == "add" for x in
                            report["tables"]["audioChestType"]["gadgetIdiomSignatureCandidates"]))
        self.assertEqual(report["tables"]["handbookOpenChest"]
                         ["literalHitByOperation"].get("xor"), 1)
        with self.assertRaisesRegex(ValueError, "source-positive signature missing"):
            mod.inspect_sections(synthetic[1:], src)

    def test_never_promotes_community_count_without_native_reader(self):
        src = {key: {"hypotheticalNativeArithmeticConstants": {
            "add": "0x00000001", "sub": "0x00000002", "xor": "0x00000003"
        }, "hypotheticalCommunityRowCount": 123} for key in mod.SOURCES}
        out = mod.inspect_sections([(mod.GADGET_POSITIVE_RVA,
                                    bytes.fromhex(mod.GADGET_POSITIVE_SIGNATURE))], src)
        self.assertEqual(out["tables"]["audioChestType"]["literalImmediateHits"], 0)
        self.assertTrue(any("not original" in s for s in out["limits"]))
        self.assertNotIn("nativeCountVerified", out)


if __name__ == "__main__":
    unittest.main()
