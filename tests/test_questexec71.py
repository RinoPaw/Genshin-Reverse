from __future__ import annotations

import struct
import unittest

from genshinre.questexec71 import (
    ARRAY_COUNT_ADD,
    MASK_ADD,
    PARAM_BLOCK_ADD,
    PARAM_COUNT_ADD,
    PARAM_COUNT_XOR,
    PARAM_LENGTH_XOR,
    TYPE_ADD,
    QuestExec71ParseError,
    parse_questexec71_array,
)


def u32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def _encode_additive_blocks(decoded: bytes, key: int) -> bytes:
    out = bytearray()
    for pos in range(0, len(decoded), 8):
        block = decoded[pos:pos + 8]
        width = len(block)
        mask = (1 << (width * 8)) - 1
        value = (
            int.from_bytes(block, "little")
            - (key & mask)
        ) & mask
        out += value.to_bytes(width, "little")
    return bytes(out)


def _param(value: str) -> bytes:
    raw = value.encode("utf-8")
    return (
        struct.pack("<H", len(raw) ^ PARAM_LENGTH_XOR)
        + _encode_additive_blocks(raw, PARAM_BLOCK_ADD)
    )


def _exec(exec_type: int, params: tuple[str, ...]) -> bytes:
    mask = (1 << 5) | (1 << 2)
    raw_mask = (mask - MASK_ADD) & 0xFF
    raw_count = (
        ((len(params) ^ PARAM_COUNT_XOR) - PARAM_COUNT_ADD)
        & 0xFFFFFFFF
    )
    out = bytearray([raw_mask])
    out += u32(raw_count)
    for value in params:
        out += _param(value)
    out += u32((exec_type - TYPE_ADD) & 0xFFFFFFFF)
    return bytes(out)


def _array(items: tuple[bytes, ...]) -> bytes:
    return u32((len(items) - ARRAY_COUNT_ADD) & 0xFFFFFFFF) + b"".join(items)


class QuestExec71Tests(unittest.TestCase):
    def test_decodes_native_array_shape(self) -> None:
        raw = _array((_exec(14, ("35100",)),))
        items, end = parse_questexec71_array(raw, 0, len(raw))
        self.assertEqual(len(raw), end)
        self.assertEqual(1, len(items))
        self.assertEqual(14, items[0].exec_type)
        self.assertEqual(("35100",), items[0].params)

    def test_decodes_multiple_utf8_params(self) -> None:
        raw = _array((_exec(3, ("3", "133003429,1", "测试")),))
        items, end = parse_questexec71_array(raw, 0, len(raw))
        self.assertEqual(len(raw), end)
        self.assertEqual(("3", "133003429,1", "测试"), items[0].params)

    def test_rejects_unknown_mask_bits(self) -> None:
        raw = _array((bytes([(1 - MASK_ADD) & 0xFF]),))
        with self.assertRaisesRegex(QuestExec71ParseError, "unsupported"):
            parse_questexec71_array(raw, 0, len(raw))


if __name__ == "__main__":
    unittest.main()
