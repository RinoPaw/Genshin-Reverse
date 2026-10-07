from __future__ import annotations

import struct
import unittest

from genshinre.questexcel71 import (
    BAN_TYPE_BY_RAW,
    BIT_BAN_TYPE,
    BIT_DMCMNPLMCKL,
    BIT_EXCLUSIVE_PLACE_LIST,
    BIT_IS_MP_BLOCK,
    BIT_ORDER,
    BIT_PREFER_AREA2_GUIDE_SCENE,
    BIT_SHOW_TYPE,
    BIT_UNKNOWN_34,
    BIT_UNKNOWN_40,
    EXCLUSIVE_PLACE_COUNT_XOR,
    DMCMNPLMCKL_HIDDEN_RAW,
    EXCLUSIVE_PLACE_ELEMENT_SUB,
    GUIDE_TIPS_TEXT_MAP_HASH_XOR,
    IS_MP_BLOCK_TRUE_RAW,
    LOW_ROW_MASKS,
    ORDER_RAW_SUB,
    PREFER_AREA2_GUIDE_SCENE_RAW,
    QuestExcel71ParseError,
    SHOW_TYPE_HIDDEN_RAW,
    STEP_DESC_TEXT_MAP_HASH_XOR,
    SUB_ID_XOR,
    UNKNOWN_BIT34_RAW,
    UNKNOWN_BIT40_RAW,
    parse_questexcel71_raw_export,
)


LOW_MASK = 0x087EFDD5


def u32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def _encode_additive_blocks(decoded: bytes, add_key: int) -> bytes:
    out = bytearray()
    for pos in range(0, len(decoded), 8):
        block = decoded[pos:pos + 8]
        width = len(block)
        mask = (1 << (width * 8)) - 1
        value = int.from_bytes(block, "little")
        encoded = (value - (add_key & mask)) & mask
        out += encoded.to_bytes(width, "little")
    return bytes(out)


def _encode_param(value: str) -> bytes:
    raw = value.encode("utf-8")
    return (
        struct.pack("<H", len(raw) ^ PARAM_LENGTH_XOR)
        + _encode_additive_blocks(raw, PARAM_BLOCK_ADD)
    )


def make_guide(
    *,
    params: tuple[str, ...] = ("", "", "", "", ""),
    guide_scene: int | None = None,
    guide_type: int | None = None,
) -> bytes:
    # All decoded-mask-gated fields absent; raw bit4 keeps the params array.
    mask_raw = 0x4DB0C853
    if guide_scene is not None:
        mask_raw |= 1 << 3
    if guide_type is not None:
        # Guide type uses decoded bit23; MASK_XOR bit23 is one.
        mask_raw &= ~(1 << 23)

    out = bytearray(u32(mask_raw))
    if guide_scene is not None:
        out += u32(guide_scene ^ 0x33876F87)
    out += u32(len(params) - PARAM_COUNT_ADD)
    for value in params:
        out += _encode_param(value)
    if guide_type is not None:
        out += u32(guide_type - 0x6FE88290)
    return bytes(out)


def make_row(
    sub_id: int,
    *,
    unknown_prefix_u32: int,
    places: tuple[int, ...] | None = None,
    prefer: bool = False,
    order: int | None = None,
    is_mp_block: bool = False,
    bit34: bool = False,
    step_desc_text_map_hash: int = 0,
    dmcmnplmckl_hidden: bool = False,
    ban_type: str | None = None,
    bit40: bool = False,
    tail: bytes = b"",
    guide: bytes | None = None,
    show_hidden: bool = False,
    guide_tips_text_map_hash: int = 0,
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
    if dmcmnplmckl_hidden:
        mask64 &= ~(1 << BIT_DMCMNPLMCKL)
    if ban_type is not None:
        mask64 &= ~(1 << BIT_BAN_TYPE)
    if bit40:
        mask64 |= 1 << BIT_UNKNOWN_40
    if show_hidden:
        mask64 &= ~(1 << BIT_SHOW_TYPE)

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
    out += u32(step_desc_text_map_hash ^ STEP_DESC_TEXT_MAP_HASH_XOR)
    if dmcmnplmckl_hidden:
        out += u32(DMCMNPLMCKL_HIDDEN_RAW)
    if ban_type is not None:
        raw_by_ban_type = {value: raw for raw, value in BAN_TYPE_BY_RAW.items()}
        out += u32(raw_by_ban_type[ban_type])
    if bit40:
        out.append(UNKNOWN_BIT40_RAW)
    out += tail
    out += make_guide() if guide is None else guide
    if show_hidden:
        out += u32(SHOW_TYPE_HIDDEN_RAW)
    out += u32(guide_tips_text_map_hash ^ GUIDE_TIPS_TEXT_MAP_HASH_XOR)
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
            step_desc_text_map_hash=0x13579BDF,
            dmcmnplmckl_hidden=True,
            ban_type="BAN_GROUP_TRANSPORT_MAP",
            bit40=True,
            tail=b"\xAA\xBB\xCC",
            guide=make_guide(
                params=("1005", "QuestArrow", "", "", ""),
                guide_scene=3,
                guide_type=2,
            ),
            guide_tips_text_map_hash=0x2468ACE0,
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
        self.assertEqual(0x13579BDF, first.step_desc_text_map_hash)
        self.assertEqual("QUEST_HIDDEN", first.dmcmnplmckl)
        self.assertEqual("BAN_GROUP_TRANSPORT_MAP", first.ban_type)
        self.assertEqual(UNKNOWN_BIT40_RAW, first.unknown_bit40_raw)
        self.assertEqual(b"\xAA\xBB\xCC", first.raw_tail)
        self.assertEqual(first.guide.start, first.known_suffix_start)
        self.assertEqual(("1005", "QuestArrow", "", "", ""), first.guide.params)
        self.assertEqual(3, first.guide.guide_scene)
        self.assertEqual(2, first.guide.guide_type)
        self.assertIsNone(first.show_type)
        self.assertEqual(0x2468ACE0, first.guide_tips_text_map_hash)

        second = table.rows[1]
        self.assertIsNone(second.exclusive_place_list)
        self.assertFalse(second.prefer_area2_guide_scene)
        self.assertIsNone(second.order)
        self.assertIsNone(second.is_mp_block)
        self.assertIsNone(second.unknown_bit34_raw)
        self.assertEqual(0, second.step_desc_text_map_hash)
        self.assertIsNone(second.dmcmnplmckl)
        self.assertIsNone(second.ban_type)
        self.assertIsNone(second.unknown_bit40_raw)
        self.assertEqual(b"opaque", second.raw_tail)
        self.assertEqual(second.guide.start, second.known_suffix_start)
        self.assertEqual(("", "", "", "", ""), second.guide.params)
        self.assertIsNone(second.show_type)
        self.assertEqual(0, second.guide_tips_text_map_hash)

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

    def test_rejects_unexpected_bit40_encoding(self) -> None:
        row = bytearray(make_row(10001, unknown_prefix_u32=0, bit40=True))
        bit40_pos = 8 + 4 + 4
        row[bit40_pos] = 0
        payload = u32(0) + row
        with self.assertRaisesRegex(QuestExcel71ParseError, "bit40 raw"):
            parse_questexcel71_raw_export(raw_export(payload), expected_row_count=1)

    def test_decodes_explicit_hidden_show_type_after_guide(self) -> None:
        row = make_row(
            10001,
            unknown_prefix_u32=0,
            show_hidden=True,
        )
        payload = u32(0) + row
        table = parse_questexcel71_raw_export(raw_export(payload), expected_row_count=1)
        self.assertEqual("QUEST_HIDDEN", table.rows[0].show_type)

    def test_rejects_unexpected_show_type_encoding(self) -> None:
        row = bytearray(
            make_row(10001, unknown_prefix_u32=0, show_hidden=True)
        )
        row[-12:-8] = u32(0xDEADBEEF)
        payload = u32(0) + row
        with self.assertRaisesRegex(QuestExcel71ParseError, "showType raw"):
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