from __future__ import annotations

import unittest

from genshinre.wire import read_varint


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


if __name__ == "__main__":
    unittest.main()
