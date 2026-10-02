from __future__ import annotations

import struct
import unittest

from genshinre.mhy71 import (
    MASK32,
    MASK64,
    _decode_parameter_span,
    _owner_array,
    decode_field_record,
    decode_method_record,
    decode_string_token,
    decode_type_record,
)
from genshinre.param71 import parameter_key


class Mhy71FormulaTests(unittest.TestCase):
    def test_type_record_formulas(self) -> None:
        record = bytearray(70)
        namespace_token = 0x12345678
        method_start = 696275
        field_start = 417613
        name_token = 0x8BADF00D
        method_count = 8
        field_count = 2

        struct.pack_into("<I", record, 0x00, (namespace_token - 0xBBB4CF40) & MASK32)
        struct.pack_into("<I", record, 0x0C, method_start ^ 0x4D8127F2)
        struct.pack_into("<I", record, 0x1C, field_start ^ 0x29010897)
        struct.pack_into("<I", record, 0x24, (name_token - 0xFBAD8E98) & MASK32)
        struct.pack_into("<H", record, 0x30, (method_count - 0x12C6) & 0xFFFF)
        struct.pack_into("<H", record, 0x38, field_count ^ 0x51A8)

        decoded = decode_type_record(bytes(record))
        self.assertEqual(namespace_token, decoded["namespace_token"])
        self.assertEqual(method_start, decoded["method_start"])
        self.assertEqual(field_start, decoded["field_start"])
        self.assertEqual(name_token, decoded["name_token"])
        self.assertEqual(method_count, decoded["method_count"])
        self.assertEqual(field_count, decoded["field_count"])

    def test_field_record_formulas_round_trip(self) -> None:
        index = 417613
        from genshinre.mhy71 import _field_key

        key = _field_key(index)
        wanted_type = 439246
        wanted_name = 0xAABBCCDD
        record = bytearray(8)
        struct.pack_into("<I", record, 0, wanted_type ^ key ^ 0x2D27D873)
        encoded_name = (((wanted_name ^ key ^ 0x2D027B84) - 0xA810CEF4) & MASK32)
        struct.pack_into("<I", record, 4, encoded_name)
        decoded = decode_field_record(bytes(record), index)
        self.assertEqual(wanted_type, decoded["type_index"])
        self.assertEqual(wanted_name, decoded["name_token"])

    def test_method_record_formulas_round_trip(self) -> None:
        index = 696275
        from genshinre.mhy71 import _method_key

        key = _method_key(index)
        name_token = 0x71234567
        parameter_start = 12345
        declaring_type = 84249
        parameter_count = 2
        record = bytearray(26)
        struct.pack_into("<I", record, 0, ((name_token ^ key) - 0xA52959D7) & MASK32)
        struct.pack_into("<I", record, 4, ((parameter_start & MASK32) ^ key) - 0xF0A05526 & MASK32)
        struct.pack_into("<I", record, 0x0C, declaring_type ^ key ^ 0x59244785)
        record[0x18] = (((parameter_count ^ (key & 0xFF)) - 0xE1) & 0xFF)
        decoded = decode_method_record(bytes(record), index)
        self.assertEqual(name_token, decoded["name_token"])
        self.assertEqual(parameter_start, decoded["parameter_start"])
        self.assertEqual(declaring_type, decoded["declaring_type_index"])
        self.assertEqual(parameter_count, decoded["parameter_count"])

    def test_parameter_span_decodes_types_for_method_output(self) -> None:
        parameter_base = 11
        parameter_start = 23
        wanted = [(248_305, 0x0B186E6D), (248_269, 0x0B18B3F4)]
        blob = bytearray(parameter_base + (parameter_start + len(wanted)) * 8)

        for ordinal, (type_index, name_token) in enumerate(wanted):
            index = parameter_start + ordinal
            key = parameter_key(index)
            offset = parameter_base + index * 8
            raw_type = type_index ^ key ^ 0x31BF59F3
            raw_name = ((name_token ^ key ^ 0x4CDBD093) - 0x96D3F6A4) & MASK32
            struct.pack_into("<II", blob, offset, raw_type, raw_name)

        names = {248_305: "ONKOPMILDMF", 248_269: "PGAMFBPNNIC"}
        indices, resolved = _decode_parameter_span(
            bytes(blob),
            parameter_base,
            parameter_start,
            len(wanted),
            lambda index: names[index],
        )
        self.assertEqual([248_305, 248_269], indices)
        self.assertEqual(["ONKOPMILDMF", "PGAMFBPNNIC"], resolved)

    def test_parameter_span_rejects_negative_start_with_nonzero_count(self) -> None:
        with self.assertRaisesRegex(ValueError, "negative parameter start"):
            _decode_parameter_span(b"", 0, -1, 1, lambda index: str(index))

    def test_owner_array_rejects_truncated_span(self) -> None:
        with self.assertRaisesRegex(ValueError, "span exceeds decoded table"):
            _owner_array(
                3,
                [
                    {
                        "type_definition_index": 7,
                        "field_start": 2,
                        "field_count": 2,
                    }
                ],
                "field_start",
                "field_count",
            )

    def test_anonymous_string_sentinel_is_empty(self) -> None:
        self.assertEqual("", decode_string_token(b"", 0, MASK32))

    def test_string_token_rejects_invalid_utf8(self) -> None:
        token = 1 << 24
        key = (0x55A357D81EF0E48B * 0x5C2B4E660E2D0544) & MASK64
        encrypted = key ^ 0xFF
        metadata = struct.pack("<Q", encrypted)
        with self.assertRaisesRegex(ValueError, "not valid UTF-8"):
            decode_string_token(metadata, 0, token)


if __name__ == "__main__":
    unittest.main()
