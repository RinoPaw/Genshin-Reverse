from __future__ import annotations

import unittest

from genshinre.typearray import (
    EXPECTED_RUNTIME_TYPE_COUNT,
    decode_type_entry,
    is_valid_type_entry,
)


class TypeArrayTests(unittest.TestCase):
    def test_class_entry(self) -> None:
        entry = bytearray(16)
        entry[0:4] = (84249).to_bytes(4, "little")
        entry[0x0A] = 0x12
        decoded = decode_type_entry(bytes(entry))
        self.assertEqual(84249, decoded["data_u32"])
        self.assertEqual(0x12, decoded["kind"])
        self.assertEqual("class", decoded["kind_name"])
        self.assertTrue(is_valid_type_entry(bytes(entry)))

    def test_valuetype_entry(self) -> None:
        entry = bytearray(16)
        entry[0:4] = (1234).to_bytes(4, "little")
        entry[0x0A] = 0x11
        decoded = decode_type_entry(bytes(entry))
        self.assertEqual("valuetype", decoded["kind_name"])
        self.assertTrue(is_valid_type_entry(bytes(entry)))

    def test_truncated_entry_rejected(self) -> None:
        with self.assertRaises(ValueError):
            decode_type_entry(b"\x00" * 15)
        self.assertFalse(is_valid_type_entry(b"\x00" * 15))

    def test_definition_outside_metadata_rejected(self) -> None:
        entry = bytearray(16)
        entry[0:4] = (88_904).to_bytes(4, "little")
        entry[0x0A] = 0x12
        self.assertFalse(is_valid_type_entry(bytes(entry)))

    def test_nonzero_trailing_padding_rejected(self) -> None:
        entry = bytearray(16)
        entry[0x0A] = 0x15
        entry[0x0C] = 1
        self.assertFalse(is_valid_type_entry(bytes(entry)))

    def test_verified_boundary_record_is_not_a_type(self) -> None:
        boundary = bytes.fromhex("8988883b0000000060da9e4501000000")
        self.assertFalse(is_valid_type_entry(boundary))

    def test_special_il2cpp_kind_is_recognized(self) -> None:
        entry = bytearray(16)
        entry[0x0A] = 0x45
        decoded = decode_type_entry(bytes(entry))
        self.assertEqual("pinned", decoded["kind_name"])
        self.assertTrue(is_valid_type_entry(bytes(entry)))

    def test_preserved_runtime_type_count(self) -> None:
        self.assertEqual(683_574, EXPECTED_RUNTIME_TYPE_COUNT)


if __name__ == "__main__":
    unittest.main()
