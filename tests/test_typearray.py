from __future__ import annotations

import unittest

from genshinre.typearray import decode_type_entry


class TypeArrayTests(unittest.TestCase):
    def test_class_entry(self) -> None:
        entry = bytearray(16)
        entry[0:4] = (84249).to_bytes(4, "little")
        entry[0x0A] = 0x12
        decoded = decode_type_entry(bytes(entry))
        self.assertEqual(84249, decoded["data_u32"])
        self.assertEqual(0x12, decoded["kind"])
        self.assertEqual("class", decoded["kind_name"])

    def test_valuetype_entry(self) -> None:
        entry = bytearray(16)
        entry[0:4] = (1234).to_bytes(4, "little")
        entry[0x0A] = 0x11
        decoded = decode_type_entry(bytes(entry))
        self.assertEqual("valuetype", decoded["kind_name"])

    def test_truncated_entry_rejected(self) -> None:
        with self.assertRaises(ValueError):
            decode_type_entry(b"\x00" * 15)


if __name__ == "__main__":
    unittest.main()
