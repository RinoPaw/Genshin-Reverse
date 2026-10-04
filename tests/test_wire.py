from __future__ import annotations

import unittest

from genshinre.wire import MAX_FIELD_NUMBER, parse_message, read_varint


def _encode_varint(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


class WireVarintTests(unittest.TestCase):
    def test_read_varint_rejects_negative_offset(self) -> None:
        with self.assertRaisesRegex(ValueError, "offset must be non-negative"):
            read_varint(b"\x01", -1)

    def test_read_varint_reports_next_offset(self) -> None:
        value, offset = read_varint(bytes.fromhex("AC02FF"))
        self.assertEqual(300, value)
        self.assertEqual(2, offset)

    def test_read_varint_accepts_uint64_max(self) -> None:
        value, offset = read_varint(bytes.fromhex("FFFFFFFFFFFFFFFFFF01"))
        self.assertEqual((1 << 64) - 1, value)
        self.assertEqual(10, offset)

    def test_read_varint_rejects_more_than_64_bits(self) -> None:
        with self.assertRaisesRegex(ValueError, "exceeds 64 bits"):
            read_varint(bytes.fromhex("FFFFFFFFFFFFFFFFFF02"))

    def test_parse_message_accepts_maximum_field_number(self) -> None:
        tag = (MAX_FIELD_NUMBER << 3) | 0
        fields = parse_message(_encode_varint(tag) + b"\x01")
        self.assertEqual(MAX_FIELD_NUMBER, fields[0]["field_number"])
        self.assertEqual(1, fields[0]["value"])

    def test_parse_message_rejects_field_number_above_protobuf_limit(self) -> None:
        tag = ((MAX_FIELD_NUMBER + 1) << 3) | 0
        with self.assertRaisesRegex(ValueError, "field number"):
            parse_message(_encode_varint(tag) + b"\x01")


if __name__ == "__main__":
    unittest.main()
