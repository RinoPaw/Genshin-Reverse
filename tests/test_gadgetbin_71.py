"""Synthetic whole-table regression tests for exact 7.1 Gadget native readers.

No original client bytes are stored in this fixture.
"""
from __future__ import annotations

import struct
import unittest

from genshinre.binconfig import decode_native_chunks
from genshinre.gadgetbin import (
    BASE_MASK_ADD, BASE_SCHEMA, BASE_STRING_KEY, HEADER_COUNT_ADD,
    MASK_ADD, SCHEMA, GadgetBinParseError, scan_gadget_payload,
    scan_gadget_raw_export,
)

U32 = 0xFFFFFFFF
U64 = 0xFFFFFFFFFFFFFFFF


def inverse(value: int, operations: tuple, width: int = 32) -> int:
    limit = (1 << width) - 1
    for op, constant in reversed(list(zip(operations[::2], operations[1::2]))):
        value = (value - constant) if op == "add" else value ^ constant
        value &= limit
    return value


def inner_string(value: str, add: int, key: int) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack("<H", (len(raw) - add) & 0xFFFF) + decode_native_chunks(raw, key, "xor")


def encode_base(fields: dict[int, object]) -> bytes:
    mask = sum(flag for flag, offset, _, _ in BASE_SCHEMA if offset in fields)
    out = bytearray(struct.pack("<H", (mask - BASE_MASK_ADD) & 0xFFFF))
    for flag, offset, kind, arg in BASE_SCHEMA:
        if not mask & flag:
            continue
        value = fields[offset]
        if kind == "d":
            out.extend(struct.pack("<I", inverse(value, arg)))
        elif kind == "q":
            out.extend(struct.pack("<Q", inverse(value, arg, 64)))
        elif kind == "string":
            raw = value.encode("utf-8")
            out.extend(struct.pack("<H", ((len(raw) ^ 0x7C82) + 0xD3) & 0xFFFF))
            out.extend(decode_native_chunks(raw, BASE_STRING_KEY, "xor"))
        else:
            raise AssertionError("unknown base fixture kind")
    return bytes(out)


def encode_inner(fields: dict[int, object]) -> bytes:
    mask = sum(1 << bit for off, bit, _, _ in SCHEMA if off in fields)
    out = bytearray(struct.pack("<Q", (mask - MASK_ADD) & U64))
    for off, bit, kind, args in SCHEMA:
        if off not in fields:
            continue
        value = fields[off]
        if kind == "b":
            out.append(((args + 1) & 255) if value else args)
        elif kind == "d":
            out.extend(struct.pack("<I", inverse(value, args)))
        elif kind == "q":
            out.extend(struct.pack("<Q", inverse(value, args, 64)))
        elif kind == "s":
            out.extend(inner_string(value, *args))
        elif kind == "a":
            count_add, length_add, key = args
            out.extend(struct.pack("<I", (len(value) - count_add) & U32))
            for item in value:
                out.extend(inner_string(item, length_add, key))
        else:
            raise AssertionError("unknown inner fixture kind")
    return bytes(out)


def fixture(rows: list[tuple[dict[int, object], dict[int, object]]]) -> bytes:
    data = bytearray(struct.pack("<I", (len(rows) - HEADER_COUNT_ADD) & U32))
    for base, inner in rows:
        data.extend(encode_base(base))
        data.extend(encode_inner(inner))
    return bytes(data)


class TestGadgetNativeTable71(unittest.TestCase):
    def setUp(self):
        self.rows = [
            ({0x30: 70210001, 0x20: 3421415086822832025, 0x34: 54268321,
              0x18: 5001},
             {0x6C: 26, 0x58: "SceneObj_Chest_NormalChest",
              0x50: "UI_Icon_Intee_TreasureBox", 0x60: "Default_Item",
              0x78: True, 0x84: 1, 0x48: ["Default", "宝箱"]}),
            ({0x30: 70210106, 0x20: 16501516784450816326, 0x34: 3840233921,
              0x10: "Gadget_Special_Small_01", 0x18: 5001},
             {0x6C: 26, 0x58: "SceneObj_Chest_Flora", 0x7D: False}),
        ]
        self.data = fixture(self.rows)

    def test_end_to_end_count_base_and_inner_bytes(self):
        scan = scan_gadget_payload(self.data, expected_rows=2)
        self.assertEqual(scan.header_count, 2)
        self.assertEqual([row.gadget_id for row in scan.rows], [70210001, 70210106])
        self.assertEqual([row.base_fields for row in scan.rows],
                         [row[0] for row in self.rows])
        self.assertEqual([row.fields for row in scan.rows],
                         [row[1] for row in self.rows])
        self.assertEqual(scan.rows[0].base_mask, 0x17)
        self.assertEqual(scan.rows[1].base_mask, 0x97)
        self.assertEqual(scan.rows[-1].inner_end, len(self.data))
        self.assertEqual(scan.summary()["headerCountDecoded"], True)
        self.assertEqual(scan.summary()["unparsedBytes"], 0)
        self.assertEqual(scan.summary()["uniqueIds"], 2)
        self.assertEqual(scan.summary()["enum26Count"], 2)
        self.assertEqual(scan.summary()["enum26DistinctNames"], 2)
        self.assertEqual(scan.base_decoded_bytes +
                         sum(row.inner_end-row.inner_start for row in scan.rows) + 4,
                         len(self.data))

    def test_original_raw_export_wrapper(self):
        raw = struct.pack("<I", len(self.data)) + self.data
        self.assertEqual(scan_gadget_raw_export(raw, expected_rows=2).header_count, 2)

    def test_header_count_and_trailing_bytes_fail_closed(self):
        with self.assertRaisesRegex(GadgetBinParseError, "header count"):
            scan_gadget_payload(self.data, expected_rows=3)
        with self.assertRaisesRegex(GadgetBinParseError, "trailing bytes"):
            scan_gadget_payload(self.data + b"\x00", expected_rows=2)
        with self.assertRaisesRegex(GadgetBinParseError, "input bounds"):
            scan_gadget_payload(struct.pack("<I", (90000 - HEADER_COUNT_ADD) & U32),
                                expected_rows=90000)

    def test_missing_native_id_and_unknown_control_bits_rejected(self):
        data = bytearray(self.data)
        mask = ((struct.unpack_from("<H", data, 4)[0] + BASE_MASK_ADD) & 0xFFFF)
        struct.pack_into("<H", data, 4, ((mask & ~0x10) - BASE_MASK_ADD) & 0xFFFF)
        with self.assertRaisesRegex(GadgetBinParseError, "ID absent"):
            scan_gadget_payload(bytes(data), expected_rows=2)
        struct.pack_into("<H", data, 4, ((0x100 | mask) - BASE_MASK_ADD) & 0xFFFF)
        with self.assertRaisesRegex(GadgetBinParseError, "base mask"):
            scan_gadget_payload(bytes(data), expected_rows=2)

    def test_duplicate_id_and_corrupted_inner_mask_rejected(self):
        scan = scan_gadget_payload(self.data, expected_rows=2)
        second = scan.rows[1]
        data = bytearray(self.data)
        start = second.base_spans[0x30][0]
        ops = next(x[3] for x in BASE_SCHEMA if x[1] == 0x30)
        struct.pack_into("<I", data, start, inverse(70210001, ops))
        with self.assertRaisesRegex(GadgetBinParseError, "duplicate"):
            scan_gadget_payload(bytes(data), expected_rows=2)
        data = bytearray(self.data)
        maskpos = scan.rows[0].inner_start
        value = struct.unpack_from("<Q", data, maskpos)[0]
        struct.pack_into("<Q", data, maskpos, value ^ (1 << 63))
        with self.assertRaisesRegex(GadgetBinParseError, "unrecognized"):
            scan_gadget_payload(bytes(data), expected_rows=2)


if __name__ == "__main__":
    unittest.main()
