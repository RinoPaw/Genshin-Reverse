from __future__ import annotations

import struct
import unittest

from genshinre.questcontent71 import (
    ARRAY_COUNT_ADD,
    ARRAY_COUNT_XOR,
    MASK_ADD,
    PARAM_COUNT_ADD,
    PARAM_ELEMENT_ADD,
    STRING_BLOCK_XOR,
    STRING_LENGTH_ADD,
    TYPE_ADD,
    TYPE_XOR,
    UNKNOWN_SCALAR_XOR,
    QuestContent71ParseError,
    parse_questcontent71_array,
)


def u32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def _encode_xor_blocks(decoded: bytes, key: int) -> bytes:
    out = bytearray()
    for pos in range(0, len(decoded), 8):
        block = decoded[pos:pos + 8]
        width = len(block)
        mask = (1 << (width * 8)) - 1
        value = int.from_bytes(block, "little") ^ (key & mask)
        out += value.to_bytes(width, "little")
    return bytes(out)


def _content(
    content_type: int,
    params: tuple[int, ...],
    *,
    string_value: str = "",
    unknown_scalar: int | None = None,
) -> bytes:
    mask = (1 << 1) | 1 | (1 << 7)
    if unknown_scalar is not None:
        mask |= 1 << 4
    raw_mask = (mask - MASK_ADD) & 0xFF
    raw_string = string_value.encode("utf-8")
    raw_type = ((content_type - TYPE_ADD) & 0xFFFFFFFF) ^ TYPE_XOR
    out = bytearray([raw_mask])
    out += struct.pack("<H", (len(raw_string) - STRING_LENGTH_ADD) & 0xFFFF)
    out += _encode_xor_blocks(raw_string, STRING_BLOCK_XOR)
    out += u32(raw_type)
    out += u32((len(params) - PARAM_COUNT_ADD) & 0xFFFFFFFF)
    for value in params:
        out += u32((value - PARAM_ELEMENT_ADD) & 0xFFFFFFFF)
    if unknown_scalar is not None:
        out += u32(unknown_scalar ^ UNKNOWN_SCALAR_XOR)
    return bytes(out)


def _array(items: tuple[bytes, ...]) -> bytes:
    raw_count = (
        ((len(items) ^ ARRAY_COUNT_XOR) - ARRAY_COUNT_ADD)
        & 0xFFFFFFFF
    )
    return u32(raw_count) + b"".join(items)


class QuestContent71Tests(unittest.TestCase):
    def test_decodes_native_array_shape(self) -> None:
        raw = _array((
            _content(4, (35100, 0)),
            _content(6, (1053, 0)),
        ))
        items, end = parse_questcontent71_array(raw, 0, len(raw))
        self.assertEqual(len(raw), end)
        self.assertEqual((4, 6), tuple(item.content_type for item in items))
        self.assertEqual((35100, 0), items[0].params)
        self.assertEqual((1053, 0), items[1].params)
        self.assertEqual("", items[0].string_value)

    def test_decodes_string_and_unknown_scalar(self) -> None:
        raw = _array((_content(
            21,
            (0, 0),
            string_value="native",
            unknown_scalar=7,
        ),))
        items, end = parse_questcontent71_array(raw, 0, len(raw))
        self.assertEqual(len(raw), end)
        self.assertEqual("native", items[0].string_value)
        self.assertEqual(7, items[0].unknown_scalar)

    def test_rejects_unknown_mask_bits(self) -> None:
        raw = bytes([((1 << 2) - MASK_ADD) & 0xFF])
        with self.assertRaisesRegex(QuestContent71ParseError, "unsupported"):
            parse_questcontent71_array(u32(
                ((1 ^ ARRAY_COUNT_XOR) - ARRAY_COUNT_ADD) & 0xFFFFFFFF
            ) + raw, 0, 5)


if __name__ == "__main__":
    unittest.main()