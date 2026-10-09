import unittest
from unittest.mock import patch

from genshinre.binconfig import BinaryConfigReader, decode_native_chunks
from genshinre.dungeonbin import (
    DungeonBinParseError, SCHEMA, count, parse_dungeon_row, scan_dungeon_table,
    string, transform, value,
)


def reader(raw):
    return BinaryConfigReader(raw, error_type=DungeonBinParseError, label='Dungeon')


class DungeonBinTests(unittest.TestCase):
    def test_schema_native_store_coverage(self):
        self.assertEqual(len(SCHEMA), 67)
        self.assertEqual(len({s[0] for s in SCHEMA}), 67)
        self.assertEqual(next(s for s in SCHEMA if s[0] == 0xE8),
                         (0xE8, 13, 0xD3D96C23, 'u', ('xor', 0x2DBB0C2F)))

    def test_wrapper_wire_control(self):
        r = reader((82162700 ^ 0x2DBB0C2F).to_bytes(4, 'little'))
        self.assertEqual(value(r, 'u', ('xor', 0x2DBB0C2F)), 82162700)
        self.assertEqual(r.pos, 4)

    def test_presence_polarity_and_spans(self):
        field = next(s for s in SCHEMA if s[0] == 0xE8)
        # This field is present when the pre-XOR mask bit 13 is clear.
        prefix = ((-0x85B5FF59) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little')
        raw = prefix + (82162700 ^ 0x2DBB0C2F).to_bytes(4, 'little')
        with patch('genshinre.dungeonbin.SCHEMA', (field,)):
            row = parse_dungeon_row(raw)
            self.assertEqual(row.fields, {0xE8: 82162700})
            self.assertEqual(row.spans, {0xE8: (8, 12)})
            self.assertEqual(row.end, 12)
            absent = ((0x2000-0x85B5FF59) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little')
            row = parse_dungeon_row(absent)
            self.assertEqual(row.fields, {})
            self.assertEqual(row.end, 8)

    def test_modular_order(self):
        self.assertEqual(transform(0xFFFFFFFF, ('add', 1, 'xor', 3)), 3)
        self.assertEqual(transform(0xFFFF, ('add', 2), 16), 1)

    def test_chunks_partial_and_carry(self):
        self.assertEqual(decode_native_chunks(bytes.fromhex('ffff01'), 1, 'add'),
                         bytes.fromhex('000002'))
        self.assertEqual(decode_native_chunks(b'\0'*9, 0x0807060504030201, 'xor'),
                         bytes(range(1, 9)) + b'\1')
        with self.assertRaises(ValueError):
            decode_native_chunks(b'x', 0, 'unsupported')

    def test_utf8_string_and_bounds(self):
        r = reader(b'\x03\x00abc')
        self.assertEqual(string(r, (('xor', 0), 0, 'xor')), 'abc')
        with self.assertRaisesRegex(DungeonBinParseError, 'truncated'):
            string(reader(b'\x03\x00ab'), (('xor', 0), 0, 'xor'))
        with self.assertRaisesRegex(DungeonBinParseError, 'UTF-8'):
            string(reader(b'\x01\x00\xff'), (('xor', 0), 0, 'xor'))

    def test_container_bound(self):
        with self.assertRaisesRegex(DungeonBinParseError, 'count'):
            count(reader(b'\x02\0\0\0abcd'), ('xor', 0), 4)
        r = reader(b'\x01\0\0\0abcd')
        self.assertEqual(count(r, ('xor', 0), 4), 1)

    def test_nested_mask_and_wire_order(self):
        raw = ((1-0xBEC1575E) & 0xFFFFFFFF).to_bytes(4, 'little')
        raw += ((12-0x6EB) & 0xFFFF).to_bytes(2, 'little')
        raw += (((7-0x96F1A4F9) & 0xFFFFFFFF) ^ 0x82D98720).to_bytes(4, 'little')
        raw += (9 ^ 0xE7641F38).to_bytes(4, 'little')
        r = reader(raw)
        self.assertEqual(value(r, 'p', None), [{'mask': 12, 'offset0': 9, 'offset4': 7}])
        self.assertEqual(r.pos, len(raw))
        with self.assertRaises(DungeonBinParseError):
            value(reader(raw[:-1]), 'p', None)

    def test_dictionary_duplicate_keys_preserved(self):
        raw = (2 ^ 0xE006E2D7).to_bytes(4, 'little')
        for key, val in [(7, 11), (7, 13)]:
            raw += (key ^ 0x9618F3DF).to_bytes(4, 'little')
            raw += (((val ^ 0xE0D3653A)-0x22CFEBA4) & 0xFFFFFFFF).to_bytes(4, 'little')
        r = reader(raw)
        self.assertEqual(value(r, 'd', None), [[7, 11], [7, 13]])
        self.assertEqual(r.pos, len(raw))

    def test_string_array_zero_and_nonempty(self):
        raw = (2 ^ 0xE4DB6143).to_bytes(4, 'little')
        for plain in [b'', b'hello']:
            raw += ((len(plain)-0x9186) & 0xFFFF).to_bytes(2, 'little')
            raw += decode_native_chunks(plain, 0xABAA33A895329186, 'xor')
        r = reader(raw)
        self.assertEqual(value(r, 't', None), ['', 'hello'])
        self.assertEqual(r.pos, len(raw))

    def test_row_truncation_and_start(self):
        for raw in (b'', b'\0'*7):
            with self.assertRaises(DungeonBinParseError):
                parse_dungeon_row(raw)
        for start in (-1, 1):
            with self.assertRaises(DungeonBinParseError):
                parse_dungeon_row(b'', start)

    def test_table_gap_explicit(self):
        with self.assertRaisesRegex(DungeonBinParseError, 'header'):
            scan_dungeon_table(b'1234')
        scan = scan_dungeon_table(b'1234', allow_opaque_header=True)
        self.assertFalse(scan.to_dict()['headerCountDecoded'])
        self.assertEqual(scan.to_dict()['status'], 'ROW_WIRE_DECODED_HEADER_UNRESOLVED')
        self.assertEqual(scan.bytes_consumed, 4)
        with self.assertRaises(DungeonBinParseError):
            scan_dungeon_table(b'1234x', allow_opaque_header=True)


if __name__ == '__main__':
    unittest.main()
