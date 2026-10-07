from __future__ import annotations

import struct
import unittest

from genshinre.questcond71 import (
    ARRAY_COUNT_ADD,
    ARRAY_COUNT_XOR,
    MASK_SUB,
    MASK_XOR,
    PARAM_COUNT_ADD,
    PARAM_COUNT_XOR,
    PARAM_ELEMENT_ADD,
    PARAM_ELEMENT_XOR,
    TYPE_ADD,
    QuestCond71ParseError,
    parse_questcond71,
    parse_questcond71_array,
)


def u16(value: int) -> bytes:
    return struct.pack("<H", value & 0xFFFF)


def u32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def raw_mask(mask: int) -> int:
    return ((mask ^ MASK_XOR) + MASK_SUB) & 0xFFFF


def encode_cond(
    *,
    params: tuple[int, ...] | None = None,
    cond_type: int | None = None,
) -> bytes:
    mask = 0
    if params is not None:
        mask |= 1 << 3
    if cond_type is not None:
        mask |= 1

    out = bytearray(u16(raw_mask(mask)))
    if params is not None:
        raw_count = (
            ((len(params) - PARAM_COUNT_ADD) & 0xFFFFFFFF)
            ^ PARAM_COUNT_XOR
        )
        out += u32(raw_count)
        for value in params:
            raw = (
                ((value ^ PARAM_ELEMENT_XOR) - PARAM_ELEMENT_ADD)
                & 0xFFFFFFFF
            )
            out += u32(raw)
    if cond_type is not None:
        out += u32(cond_type - TYPE_ADD)
    return bytes(out)


def encode_array(items: tuple[bytes, ...]) -> bytes:
    raw_count = (
        ((len(items) - ARRAY_COUNT_ADD) & 0xFFFFFFFF)
        ^ ARRAY_COUNT_XOR
    )
    return u32(raw_count) + b"".join(items)


class QuestCond71Tests(unittest.TestCase):
    def test_decodes_state_style_condition_shape(self) -> None:
        raw = encode_cond(params=(35100, 3, 0), cond_type=1)
        item = parse_questcond71(raw, 0, len(raw))
        self.assertEqual((35100, 3, 0), item.params)
        self.assertEqual(1, item.cond_type)
        self.assertEqual(len(raw), item.end)

    def test_decodes_empty_condition(self) -> None:
        raw = encode_cond()
        item = parse_questcond71(raw, 0, len(raw))
        self.assertIsNone(item.params)
        self.assertIsNone(item.cond_type)
        self.assertEqual(len(raw), item.end)

    def test_decodes_condition_array(self) -> None:
        raw = encode_array((
            encode_cond(params=(35100, 3, 0), cond_type=1),
            encode_cond(params=(35105, 3, 0), cond_type=2),
        ))
        items, end = parse_questcond71_array(raw, 0, len(raw))
        self.assertEqual(2, len(items))
        self.assertEqual((35100, 3, 0), items[0].params)
        self.assertEqual(1, items[0].cond_type)
        self.assertEqual((35105, 3, 0), items[1].params)
        self.assertEqual(2, items[1].cond_type)
        self.assertEqual(len(raw), end)

    def test_rejects_unknown_mask_bits(self) -> None:
        raw = u16(raw_mask(1 << 2))
        with self.assertRaisesRegex(QuestCond71ParseError, "unsupported"):
            parse_questcond71(raw, 0, len(raw))

    def test_rejects_implausible_array_count(self) -> None:
        raw_count = (
            ((5000 - ARRAY_COUNT_ADD) & 0xFFFFFFFF)
            ^ ARRAY_COUNT_XOR
        )
        with self.assertRaisesRegex(QuestCond71ParseError, "array count"):
            parse_questcond71_array(u32(raw_count), 0, 4)


if __name__ == "__main__":
    unittest.main()
