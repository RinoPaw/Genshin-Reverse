"""Synthetic, source-independent regression tests for the exact 7.1 Gadget inner-record reader.

No copyrighted raw table bytes are embedded. The physical 7.1 binary is only
accepted by the separately SHA-256-pinned audit command.
"""
from __future__ import annotations

import struct
import unittest

from genshinre.binconfig import decode_native_chunks
from genshinre.gadgetbin import (
    ID_ADD_CANDIDATE, MASK_ADD, SCHEMA, GadgetBinParseError,
    read_inner_row, scan_gadget_payload, scan_gadget_raw_export,
)

U32 = 0xFFFFFFFF
U64 = 0xFFFFFFFFFFFFFFFF


def inverse(value: int, ops: tuple, width: int = 32) -> int:
    limit = (1 << width) - 1
    pairs = list(zip(ops[::2], ops[1::2]))
    for op, constant in reversed(pairs):
        if op == "add":
            value = (value - constant) & limit
        elif op == "xor":
            value = (value ^ constant) & limit
        else:
            raise AssertionError("test fixture used unknown wire operation")
    return value


def string(value: str, length_add: int, key: int) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack("<H", (len(raw) - length_add) & 0xFFFF) + decode_native_chunks(raw, key, "xor")


def encode_inner(values: dict[int, object]) -> bytes:
    mask = sum(1 << bit for offset, bit, _, _ in SCHEMA if offset in values)
    result = bytearray(struct.pack("<Q", (mask - MASK_ADD) & U64))
    for offset, bit, kind, args in SCHEMA:
        if offset not in values:
            continue
        value = values[offset]
        if kind == "b":
            result.append((args + 1) & 0xFF if value else args)
        elif kind == "d":
            result.extend(struct.pack("<I", inverse(value, args)))
        elif kind == "q":
            result.extend(struct.pack("<Q", inverse(value, args, 64)))
        elif kind == "s":
            result.extend(string(value, *args))
        elif kind == "a":
            count_add, length_add, key = args
            result.extend(struct.pack("<I", (len(value) - count_add) & U32))
            for item in value:
                result.extend(string(item, length_add, key))
        else:
            raise AssertionError("fixture has unknown field kind")
    return bytes(result)


def encode_table(rows: list[tuple[int, dict[int, object]]]) -> bytes:
    result = bytearray(b"\x29\xcc\x0a\xdc")  # Deliberately opaque synthetic header.
    for i, (id_, values) in enumerate(rows):
        # Variable, deliberately uninterpreted synthetic parent prefix.
        prefix = b"\x91\xab" + bytes([0x30 + i]) * (14 if i == 0 else 6)
        result.extend(prefix)
        result.extend(struct.pack("<I", (id_ - ID_ADD_CANDIDATE) & U32))
        result.extend(encode_inner(values))
    return bytes(result)


class TestGadgetInnerWire71(unittest.TestCase):
    def setUp(self):
        self.values = [
            (70210001, {
                0x6C: 26, 0x58: "SceneObj_Chest_NormalChest",
                0x50: "UI_Icon_Intee_TreasureBox", 0x60: "Default_Item",
                0x78: True, 0x84: 1, 0x48: ["Default", "宝箱"],
            }),
            (70210002, {0x6C: 26, 0x58: "SceneObj_Chest_NormalChest", 0x7D: False}),
        ]
        self.payload = encode_table(self.values)

    def test_full_synthetic_row_consumption(self):
        scan = scan_gadget_payload(self.payload, expected_rows=2)
        self.assertEqual(len(scan.rows), 2)
        self.assertEqual([r.id_candidate for r in scan.rows], [70210001, 70210002])
        self.assertEqual([r.fields for r in scan.rows],
                         [self.values[0][1], self.values[1][1]])
        self.assertEqual(scan.rows[-1].inner_end, len(self.payload))
        self.assertEqual(scan.opaque_header_hex, "29cc0adc")
        self.assertEqual(scan.outer_prefix_bytes +
                         sum(r.inner_end - r.inner_start for r in scan.rows) + 4,
                         len(self.payload))
        self.assertEqual(scan.summary()["enum26CountCandidate"], 2)
        self.assertEqual(scan.summary()["enum26DistinctNamesCandidate"], 1)
        self.assertEqual(scan.summary()["fieldPresentCounts"]["0x6C"], 2)

    def test_native_export_length_wrapper(self):
        raw = struct.pack("<I", len(self.payload)) + self.payload
        scan = scan_gadget_raw_export(raw, expected_rows=2)
        self.assertEqual([r.id_candidate for r in scan.rows], [70210001, 70210002])

    def test_marker_count_and_truncated_end_fail_closed(self):
        with self.assertRaisesRegex(GadgetBinParseError, "markers"):
            scan_gadget_payload(self.payload, expected_rows=3)
        with self.assertRaisesRegex(GadgetBinParseError, "reach EOF"):
            scan_gadget_payload(self.payload + b"garbage", expected_rows=2)

    def test_unrecognized_presence_bit_fails_closed(self):
        mutated = bytearray(self.payload)
        mask_start = 4 + 16 + 4
        wire_mask = struct.unpack_from("<Q", mutated, mask_start)[0]
        struct.pack_into("<Q", mutated, mask_start, (wire_mask + (1 << 63)) & U64)
        with self.assertRaisesRegex(GadgetBinParseError, "unrecognized"):
            read_inner_row(bytes(mutated), mask_start)

    def test_duplicate_id_fail_closed(self):
        mutated = bytearray(self.payload)
        second = scan_gadget_payload(self.payload, expected_rows=2).rows[1]
        struct.pack_into("<I", mutated, second.id_wire_offset,
                         (70210001 - ID_ADD_CANDIDATE) & U32)
        with self.assertRaisesRegex(GadgetBinParseError, "duplicate"):
            scan_gadget_payload(bytes(mutated), expected_rows=2)


if __name__ == "__main__":
    unittest.main()
