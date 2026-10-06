from __future__ import annotations

import unittest

from genshinre.questlegacy import (
    LegacyQuestParseError,
    detect_legacy_quest_xor_key,
    find_quest_rows,
    parse_legacy_quest_prefix,
    read_svar,
    read_uvar,
)


def _uvar(value: int) -> bytes:
    if value < 0:
        raise ValueError(value)
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _svar(value: int) -> bytes:
    unsigned = (value << 1) ^ (value >> 63)
    return _uvar(unsigned)


def _string(value: str) -> bytes:
    raw = value.encode("utf-8")
    return _uvar(len(raw)) + raw


def _row(sub_id: int, main_id: int, order: int) -> bytes:
    # Presence bits 0,1,2,10,11,24:
    # subId, mainId, order, acceptCondComb, acceptCond, beginExec.
    bits = bytes((0x07, 0x0C, 0x00, 0x01))
    accept_cond = (
        _svar(1)
        + _uvar(1)
        + bytes((0x03,))
        + _svar(1)
        + _uvar(2)
        + _svar(sub_id - 1)
        + _svar(3)
    )
    begin_exec = (
        _svar(1)
        + _uvar(1)
        + bytes((0x03,))
        + _svar(14)
        + _uvar(1)
        + _string(str(sub_id - 1))
    )
    return (
        _uvar(len(bits))
        + bits
        + _uvar(sub_id)
        + _uvar(main_id)
        + _svar(order)
        + _svar(1)
        + accept_cond
        + begin_exec
    )


def _raw_export(payload: bytes, key: int) -> bytes:
    encrypted = bytes(value ^ key for value in payload)
    return len(encrypted).to_bytes(4, "little") + encrypted


class LegacyQuestTests(unittest.TestCase):
    def test_varints_match_binarytool_zigzag_shape(self) -> None:
        data = _uvar(35104) + _svar(-7)
        unsigned, pos = read_uvar(data, 0)
        signed, end = read_svar(data, pos)
        self.assertEqual(35104, unsigned)
        self.assertEqual(-7, signed)
        self.assertEqual(len(data), end)

    def test_parses_high_value_legacy_quest_fields(self) -> None:
        payload = _svar(1) + _row(35101, 351, 4)
        prefix = parse_legacy_quest_prefix(
            _raw_export(payload, 0x93),
            xor_key=0x93,
            max_rows=1,
        )
        self.assertEqual(1, prefix.row_count)
        row = prefix.rows[0]
        self.assertEqual(35101, row.fields["sub_id"])
        self.assertEqual(351, row.fields["main_id"])
        self.assertEqual(4, row.fields["order"])
        self.assertEqual(1, row.fields["accept_cond_comb"])
        self.assertEqual(
            [{"bitfield": "03", "type": 1, "param": [35100, 3]}],
            row.fields["accept_cond"],
        )
        self.assertEqual(
            [{"bitfield": "03", "type": 14, "param": ["35100"]}],
            row.fields["begin_exec"],
        )

    def test_detects_single_byte_xor_from_structural_prefix(self) -> None:
        rows = b"".join(_row(10000 + i, 100 + i // 2, i + 1) for i in range(12))
        raw = _raw_export(_svar(12) + rows, 0x95)
        key, count = detect_legacy_quest_xor_key(
            raw,
            probe_rows=12,
            min_row_count=1,
            max_row_count=100,
        )
        self.assertEqual(0x95, key)
        self.assertEqual(12, count)

    def test_find_quest_rows_filters_decoded_prefix(self) -> None:
        rows = _row(35100, 351, 2) + _row(35200, 352, 1)
        prefix = parse_legacy_quest_prefix(
            _raw_export(_svar(2) + rows, 0x93),
            xor_key=0x93,
            max_rows=2,
        )
        matches = find_quest_rows(prefix, main_id=351)
        self.assertEqual([35100], [row.fields["sub_id"] for row in matches])

    def test_rejects_wrong_xor_key(self) -> None:
        raw = _raw_export(_svar(1) + _row(35100, 351, 2), 0x93)
        with self.assertRaises(LegacyQuestParseError):
            parse_legacy_quest_prefix(raw, xor_key=0x92, max_rows=1)


if __name__ == "__main__":
    unittest.main()
