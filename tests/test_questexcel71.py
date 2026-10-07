from __future__ import annotations

import struct
import unittest

from genshinre.questexcel71 import (
    BIT_EXCLUSIVE_PLACE_LIST,
    BIT_IS_MP_BLOCK,
    BIT_ORDER,
    BIT_PREFER_AREA2_GUIDE_SCENE,
    BIT_UNKNOWN_34,
    EXCLUSIVE_PLACE_COUNT_XOR,
    EXCLUSIVE_PLACE_ELEMENT_SUB,
    IS_MP_BLOCK_TRUE_RAW,
    LOW_ROW_MASKS,
    ORDER_RAW_SUB,
    PREFER_AREA2_GUIDE_SCENE_RAW,
    QuestExcel71ParseError,
    SUB_ID_XOR,
    UNKNOWN_BIT34_RAW,
    parse_questexcel71_raw_export,
)


LOW_MASK = 0x087EFDD5


def u32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def make_row(
    sub_id: int,
    *,
    unknown_prefix_u32: int,
    places: tuple[int, ...] | None = None,
    prefer: bool = False,
    order: int | None = None,
    is_mp_block: bool = False,
    bit34: bool = False,
    tail: bytes = b"",
) -> bytes:
    mask64 = LOW_MASK
    if places is not None:
        mask64 |= 1 << BIT_EXCLUSIVE_PLACE_LIST
    if prefer:
        mask64 |= 1 << BIT_PREFER_AREA2_GUIDE_SCENE
    if order is not None:
        mask64 |= 1 << BIT_ORDER
    if is_mp_block:
        mask64 |= 1 << BIT_IS_MP_BLOCK
    if bit34:
        mask64 |= 1 << BIT_UNKNOWN_34

    out = bytearray(struct.pack("<Q", mask64))
    out += u32(unknown_prefix_u32)
    if places is not None:
        out += u32(len(places) ^ EXCLUSIVE_PLACE_COUNT_XOR)
        for value in places:
            out += u32(value + EXCLUSIVE_PLACE_ELEMENT_SUB)
    if prefer:
        out += u32(PREFER_AREA2_GUIDE_SCENE_RAW)
    if order is not None:
        out += u32(order + ORDER_RAW_SUB)
    if is_mp_block:
        out.append(IS_MP_BLOCK_TRUE_RAW)
    if bit34:
        out += u32(UNKNOWN_BIT34_RAW)
    out += tail
    out += u32(sub_id ^ SUB_ID_XOR)
    return bytes(out)


def raw_export(payload: bytes) -> bytes:
    return u32(len(payload)) + payload


class QuestExcel71Tests(unittest.TestCase):
    def test_frames_rows_and_decodes_only_proven_prefix(self) -> None:
        row0 = make_row(
            35101,
            unknown_prefix_u32=0x12345678,
            places=(3, 7),
            prefer=True,
            order=4,
            is_mp_block=True,
            bit34=True,
            tail=b"\xAA\xBB\xCC",
        )
        row1 = make_row(
            7601112,
            unknown_prefix_u32=0x89ABCDEF,
            tail=b"opaque",
        )
        payload = u32(0xCAFEBABE) + row0 + row1

        table = parse_questexcel71_raw_export(raw_export(payload), expected_row_count=2)
        self.assertEqual(0xCAFEBABE, table.table_header_u32)
        self.assertEqual(len(payload), table.framed_bytes)
        self.assertEqual([35101, 7601112], [row.sub_id for row in table.rows])

        first = table.rows[0]
        self.assertEqual(0x12345678, first.unknown_prefix_u32)
        self.assertEqual((3, 7), first.exclusive_place_list)
        self.assertTrue(first.prefer_area2_guide_scene)
        self.assertEqual(4, first.order)
        self.assertIs(first.is_mp_block, True)
        self.assertEqual(UNKNOWN_BIT34_RAW, first.unknown_bit34_raw)
        self.assertEqual(b"\xAA\xBB\xCC", first.raw_tail)

        second = table.rows[1]
        self.assertIsNone(second.exclusive_place_list)
        self.assertFalse(second.prefer_area2_guide_scene)
        self.assertIsNone(second.order)
        self.assertIsNone(second.is_mp_block)
        self.assertIsNone(second.unknown_bit34_raw)
        self.assertEqual(b"opaque", second.raw_tail)

    def test_rejects_unexpected_bit52_encoding(self) -> None:
        row = bytearray(
            make_row(10001, unknown_prefix_u32=0, order=1, is_mp_block=True)
        )
        mp_pos = 8 + 4 + 4
        row[mp_pos] = 0
        payload = u32(0) + row
        with self.assertRaisesRegex(QuestExcel71ParseError, "bit52 raw"):
            parse_questexcel71_raw_export(raw_export(payload), expected_row_count=1)

    def test_rejects_unexpected_bit34_encoding(self) -> None:
        row = bytearray(make_row(10001, unknown_prefix_u32=0, bit34=True))
        raw_pos = 8 + 4
        row[raw_pos:raw_pos + 4] = u32(0xDEADBEEF)
        payload = u32(0) + row
        with self.assertRaisesRegex(QuestExcel71ParseError, "bit34 raw"):
            parse_questexcel71_raw_export(raw_export(payload), expected_row_count=1)

    def test_rejects_unexpected_prefer_encoding(self) -> None:
        row = bytearray(make_row(10001, unknown_prefix_u32=0, prefer=True))
        raw_pos = 8 + 4
        row[raw_pos:raw_pos + 4] = u32(0)
        payload = u32(0) + row
        with self.assertRaisesRegex(QuestExcel71ParseError, "bit29 raw"):
            parse_questexcel71_raw_export(raw_export(payload), expected_row_count=1)

    def test_rejects_duplicate_subids(self) -> None:
        payload = (
            u32(0)
            + make_row(10001, unknown_prefix_u32=1)
            + make_row(10001, unknown_prefix_u32=2)
        )
        with self.assertRaisesRegex(QuestExcel71ParseError, "duplicate"):
            parse_questexcel71_raw_export(raw_export(payload), expected_row_count=2)


if __name__ == "__main__":
    unittest.main()
