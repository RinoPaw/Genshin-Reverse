from __future__ import annotations

import unittest

from genshinre.usagesource import ANCHOR_TYPE_INDEX, TYPE_ENTRY_SIZE, classify_source_value


class UsageSourceTests(unittest.TestCase):
    def test_direct_type_index(self) -> None:
        rows = classify_source_value(ANCHOR_TYPE_INDEX, 0x140800000)
        self.assertTrue(any(row["kind"] == "direct-type-index" for row in rows))

    def test_low29_encoded_type_index(self) -> None:
        encoded = (1 << 29) | ANCHOR_TYPE_INDEX
        rows = classify_source_value(encoded, 0x140800000)
        row = next(item for item in rows if item["kind"] == "low29-encoded-index")
        self.assertEqual(ANCHOR_TYPE_INDEX, row["decoded_type_index"])
        self.assertEqual(1, row["encoded_usage_kind"])

    def test_runtime_type_entry_pointer(self) -> None:
        base = 0x140800000
        pointer = base + ANCHOR_TYPE_INDEX * TYPE_ENTRY_SIZE
        rows = classify_source_value(pointer, base)
        self.assertTrue(any(row["kind"] == "runtime-type-entry-pointer" for row in rows))

    def test_unrelated_value(self) -> None:
        self.assertEqual([], classify_source_value(1234, 0x140800000))


if __name__ == "__main__":
    unittest.main()
