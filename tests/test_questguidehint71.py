from __future__ import annotations

import struct
import unittest

from genshinre.questguidehint71 import (
    BIT_PARAM1,
    BIT_PARAM2,
    BIT_TYPE,
    MASK_ADD,
    MASK_XOR,
    PARAM1_BLOCK_ADD,
    PARAM1_LENGTH_XOR,
    PARAM2_BLOCK_XOR,
    PARAM2_LENGTH_ADD,
    TYPE_ADD,
    TYPE_XOR,
    QuestGuideHint71ParseError,
    parse_questguidehint71,
)


def _encode_blocks(decoded: bytes, key: int, *, xor: bool) -> bytes:
    out = bytearray()
    for pos in range(0, len(decoded), 8):
        block = decoded[pos:pos + 8]
        width = len(block)
        mask = (1 << (width * 8)) - 1
        value = int.from_bytes(block, "little")
        if xor:
            encoded = value ^ (key & mask)
        else:
            encoded = (value - (key & mask)) & mask
        out += encoded.to_bytes(width, "little")
    return bytes(out)


def _raw_mask(mask: int) -> int:
    return ((mask - MASK_ADD) & 0xFFFF) ^ MASK_XOR


def _encode_param2(value: str) -> bytes:
    raw = value.encode("utf-8")
    length = (len(raw) - PARAM2_LENGTH_ADD) & 0xFFFF
    return struct.pack("<H", length) + _encode_blocks(
        raw, PARAM2_BLOCK_XOR, xor=True
    )


def _encode_type(value: int) -> bytes:
    raw = ((value - TYPE_ADD) & 0xFFFFFFFF) ^ TYPE_XOR
    return struct.pack("<I", raw)


def _encode_param1(value: str) -> bytes:
    raw = value.encode("utf-8")
    return (
        struct.pack("<H", len(raw) ^ PARAM1_LENGTH_XOR)
        + _encode_blocks(raw, PARAM1_BLOCK_ADD, xor=False)
    )


class QuestGuideHint71Tests(unittest.TestCase):
    def test_decodes_exact_observed_empty_mask(self) -> None:
        raw = bytes.fromhex("3893")
        item = parse_questguidehint71(raw, 0, len(raw))
        self.assertEqual(0x9338, item.mask_raw)
        self.assertEqual(0, item.mask)
        self.assertIsNone(item.param2)
        self.assertIsNone(item.guide_type)
        self.assertIsNone(item.param1)
        self.assertEqual(2, item.end)

    def test_decodes_type_and_param1(self) -> None:
        mask = (1 << BIT_TYPE) | (1 << BIT_PARAM1)
        raw = (
            struct.pack("<H", _raw_mask(mask))
            + _encode_type(1)
            + _encode_param1("121233")
        )
        self.assertEqual(bytes.fromhex("3293"), raw[:2])

        item = parse_questguidehint71(raw, 0, len(raw))
        self.assertEqual(mask, item.mask)
        self.assertEqual(1, item.guide_type)
        self.assertEqual("121233", item.param1)
        self.assertIsNone(item.param2)
        self.assertEqual(len(raw), item.end)

    def test_decodes_param2(self) -> None:
        mask = 1 << BIT_PARAM2
        raw = struct.pack("<H", _raw_mask(mask)) + _encode_param2("o1")
        self.assertEqual(bytes.fromhex("5893"), raw[:2])

        item = parse_questguidehint71(raw, 0, len(raw))
        self.assertEqual(mask, item.mask)
        self.assertEqual("o1", item.param2)
        self.assertIsNone(item.guide_type)
        self.assertIsNone(item.param1)
        self.assertEqual(len(raw), item.end)

    def test_decodes_all_reader_fields_in_native_order(self) -> None:
        mask = (1 << BIT_PARAM2) | (1 << BIT_TYPE) | (1 << BIT_PARAM1)
        raw = (
            struct.pack("<H", _raw_mask(mask))
            + _encode_param2("left")
            + _encode_type(8)
            + _encode_param1("3:1717.63,253,9741.56")
        )
        item = parse_questguidehint71(raw, 0, len(raw))
        self.assertEqual("left", item.param2)
        self.assertEqual(8, item.guide_type)
        self.assertEqual("3:1717.63,253,9741.56", item.param1)
        self.assertEqual(len(raw), item.end)

    def test_rejects_unknown_decoded_mask_bits(self) -> None:
        raw = struct.pack("<H", _raw_mask(1 << 0))
        with self.assertRaisesRegex(QuestGuideHint71ParseError, "unsupported"):
            parse_questguidehint71(raw, 0, len(raw))


if __name__ == "__main__":
    unittest.main()
