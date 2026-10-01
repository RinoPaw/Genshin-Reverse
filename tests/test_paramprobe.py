from __future__ import annotations

import unittest

from genshinre.paramprobe import _comparisons, _u32_words


class ParameterProbeHelpersTests(unittest.TestCase):
    def test_u32_words_are_little_endian(self) -> None:
        self.assertEqual(
            _u32_words(bytes.fromhex("78563412efcdab90")),
            ["0x12345678", "0x90ABCDEF"],
        )

    def test_comparisons_include_reversible_deltas(self) -> None:
        rows = _comparisons((0x12345678).to_bytes(4, "little"), [0x00001234])
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["word_offset"], 0)
        self.assertEqual(row["raw_u32"], "0x12345678")
        self.assertEqual(row["expected_type_index"], 0x1234)
        self.assertEqual(row["raw_xor_expected"], f"0x{(0x12345678 ^ 0x1234):08X}")
        self.assertEqual(row["raw_minus_expected"], f"0x{(0x12345678 - 0x1234) & 0xFFFFFFFF:08X}")
        self.assertEqual(row["expected_minus_raw"], f"0x{(0x1234 - 0x12345678) & 0xFFFFFFFF:08X}")


if __name__ == "__main__":
    unittest.main()
