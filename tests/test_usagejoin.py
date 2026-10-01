from __future__ import annotations

import unittest

from genshinre.usagejoin import _select_anchor_match, decode_source_value
from genshinre.usagesource import ANCHOR_TYPE_INDEX, TYPE_ENTRY_SIZE


class UsageJoinTests(unittest.TestCase):
    def test_decode_source_encodings(self) -> None:
        type_array_va = 0x140800000
        direct, kind = decode_source_value(ANCHOR_TYPE_INDEX, "direct-type-index", type_array_va)
        self.assertEqual(ANCHOR_TYPE_INDEX, direct)
        self.assertIsNone(kind)

        encoded = (1 << 29) | ANCHOR_TYPE_INDEX
        decoded, kind = decode_source_value(encoded, "low29-encoded-index", type_array_va)
        self.assertEqual(ANCHOR_TYPE_INDEX, decoded)
        self.assertEqual(1, kind)

        pointer = type_array_va + ANCHOR_TYPE_INDEX * TYPE_ENTRY_SIZE
        decoded, kind = decode_source_value(pointer, "runtime-type-entry-pointer", type_array_va)
        self.assertEqual(ANCHOR_TYPE_INDEX, decoded)
        self.assertIsNone(kind)

    def test_select_unique_anchor_match(self) -> None:
        matches = [
            {
                "table_rva": "0x123400",
                "stride": 4,
                "width": 4,
                "classifications": [
                    {
                        "kind": "low29-encoded-index",
                        "decoded_type_index": ANCHOR_TYPE_INDEX,
                        "encoded_usage_kind": 1,
                    }
                ],
            }
        ]
        selected, encoding = _select_anchor_match(matches)
        self.assertEqual("0x123400", selected["table_rva"])
        self.assertEqual("low29-encoded-index", encoding)

    def test_ambiguous_anchor_rejected(self) -> None:
        matches = [
            {
                "table_rva": "0x123400",
                "stride": 4,
                "width": 4,
                "classifications": [{"kind": "direct-type-index", "decoded_type_index": ANCHOR_TYPE_INDEX}],
            },
            {
                "table_rva": "0x567800",
                "stride": 4,
                "width": 4,
                "classifications": [{"kind": "direct-type-index", "decoded_type_index": ANCHOR_TYPE_INDEX}],
            },
        ]
        with self.assertRaises(ValueError):
            _select_anchor_match(matches)


if __name__ == "__main__":
    unittest.main()
