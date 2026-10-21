"""Synthetic checks for native 7.1 Gadget header and inherited-wire decoder."""
from __future__ import annotations

import struct
import unittest

from genshinre.binconfig import decode_native_chunks
from genshinre.gadgetbin import MASK_ADD
from genshinre.gadgetnative71 import (
    BASE_MASK_ADD, BASE_STRING_KEY, TABLE_COUNT_ADD, NativeGadgetTableError,
    scan_native_gadget_table, decode_header_count,
)

U16 = 0xFFFF
U32 = 0xFFFFFFFF
U64 = 0xFFFFFFFFFFFFFFFF


def encode_base(mask, fields):
    result = bytearray(struct.pack("<H", (mask - BASE_MASK_ADD) & U16))
    if mask & 0x20:
        result += struct.pack("<Q", fields[0x40] ^ 0xA269090E)
    if mask & 0x04:
        result += struct.pack("<Q", fields[0x20] ^ 0x67754856)
    if mask & 0x01:
        result += struct.pack("<I", (fields[0x34] - 0xCFCCA56B) & U32)
    if mask & 0x80:
        raw = fields[0x10].encode("utf-8")
        result += struct.pack("<H", ((len(raw) ^ 0x7C82) + 0xD3) & U16)
        result += decode_native_chunks(raw, BASE_STRING_KEY, "xor")
    if mask & 0x02:
        result += struct.pack("<I", (fields[0x18] - 0xC6E69CA5) & U32)
    if mask & 0x08:
        result += struct.pack("<Q", fields[0x38] ^ 0xA3ED922C)
    if mask & 0x40:
        result += struct.pack("<Q", ((fields[0x28] ^ 0x87A58EB3) - 0xCD92A1B8) & U64)
    if mask & 0x10:
        result += struct.pack("<I", (fields[0x30] - 0x4894CEA6) & U32)
    return bytes(result)


def fixture(rows):
    payload = bytearray(struct.pack("<I", (len(rows) - TABLE_COUNT_ADD) & U32))
    for mask, base_fields, inner_type in rows:
        payload += encode_base(mask, base_fields)
        bitmask = (1 << 7) if inner_type is not None else 0
        payload += struct.pack("<Q", (bitmask - MASK_ADD) & U64)
        if inner_type is not None:
            # 0x6C: add 0x9F6DBCA6 then xor 0x0C064DBA
            payload += struct.pack("<I",
                ((inner_type ^ 0x0C064DBA) - 0x9F6DBCA6) & U32)
    return bytes(payload)


class TestNativeGadgetTable71(unittest.TestCase):
    def setUp(self):
        self.rows = [
            (0x17, {0x20: 0x1357, 0x34: 17, 0x18: 1001, 0x30: 70210001}, 26),
            (0x97, {0x20: 0xCAFE, 0x34: 24, 0x10: "Gadget_测试_01",
                    0x18: 0, 0x30: 70210002}, 26),
            (0xFF, {0x40: 0x1234567890123456, 0x20: 0x9ABCDEF123456789,
                    0x34: 7, 0x10: "", 0x18: 300, 0x38: 0x1111222233334444,
                    0x28: 0x9999AAAABBBBCCCC, 0x30: 70210003}, None),
        ]
        self.payload = fixture(self.rows)

    def test_header_and_complete_sequential_row_decoding(self):
        self.assertEqual(decode_header_count(self.payload), 3)
        table = scan_native_gadget_table(self.payload, expected_rows=3)
        self.assertEqual(table.consumed, len(self.payload))
        self.assertEqual(table.header_count, 3)
        self.assertEqual([r.id_scalar_candidate for r in table.rows],
                         [70210001, 70210002, 70210003])
        self.assertEqual([r.inherited_mask for r in table.rows], [0x17, 0x97, 0xFF])
        self.assertEqual([r.inherited_fields for r in table.rows],
                         [x[1] for x in self.rows])
        self.assertEqual([r.gadget_fields.get(0x6C) for r in table.rows],
                         [26, 26, None])
        for row in table.rows:
            self.assertLess(row.start, row.inherited_end)
            self.assertLess(row.inherited_end, row.end)
        summary = table.summary()
        self.assertTrue(summary["headerCountDecoded"])
        self.assertEqual(summary["chestType26CountCandidate"], 2)
        self.assertEqual(summary["inheritedMaskHistogram"],
                         {"0x17": 1, "0x97": 1, "0xFF": 1})
        self.assertEqual(summary["inheritedStringCounts"], {"": 1, "Gadget_测试_01": 1})
        self.assertEqual(summary["inheritedWireBytes"] +
                         summary["gadgetWireBytes"] + 4, len(self.payload))

    def test_header_count_and_trailing_bytes_fail_closed(self):
        with self.assertRaisesRegex(NativeGadgetTableError, "expected"):
            scan_native_gadget_table(self.payload, expected_rows=4)
        changed = bytearray(self.payload)
        changed[:4] = struct.pack("<I", (4 - TABLE_COUNT_ADD) & U32)
        with self.assertRaises(ValueError):
            scan_native_gadget_table(bytes(changed))
        with self.assertRaisesRegex(NativeGadgetTableError, "trailing"):
            scan_native_gadget_table(self.payload + b"\0")

    def test_duplicate_or_absent_native_id_rejected(self):
        duplicate = fixture([
            self.rows[0],
            (0x17, {0x20: 0, 0x34: 0, 0x18: 0, 0x30: 70210001}, None)
        ])
        with self.assertRaisesRegex(NativeGadgetTableError, "duplicate"):
            scan_native_gadget_table(duplicate)
        absent = fixture([(0x07, {0x20: 0, 0x34: 0, 0x18: 0}, None)])
        with self.assertRaisesRegex(NativeGadgetTableError, "lacks required"):
            scan_native_gadget_table(absent)

    def test_bad_flags_and_truncated_string_rejected(self):
        changed = bytearray(self.payload)
        changed[4:6] = struct.pack("<H", (0x117 - BASE_MASK_ADD) & U16)
        with self.assertRaisesRegex(NativeGadgetTableError, "unrecognized"):
            scan_native_gadget_table(bytes(changed))
        wrong = fixture([(0x91, {0x34: 1, 0x10: "ABC", 0x30: 70210001}, None)])
        corrupted = bytearray(wrong)
        # Header(4) + mask(2) + 0x34(4) => encoded u16 string length.
        corrupted[10:12] = struct.pack("<H", ((600 ^ 0x7C82) + 0xD3) & U16)
        with self.assertRaisesRegex(NativeGadgetTableError, "truncated inherited"):
            scan_native_gadget_table(bytes(corrupted))


if __name__ == "__main__":
    unittest.main()
