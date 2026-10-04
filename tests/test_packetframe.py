from __future__ import annotations

import unittest

from genshinre.packetframe import describe_frames, parse_frames, parse_hex


def _frame(cmd_id: int, head: bytes = b"", body: bytes = b"") -> bytes:
    return (
        b"\x45\x67"
        + cmd_id.to_bytes(2, "big")
        + len(head).to_bytes(2, "big")
        + len(body).to_bytes(4, "big")
        + head
        + body
        + b"\x89\xAB"
    )


class PacketFrameTests(unittest.TestCase):
    def test_parse_frames_preserves_frame_fields(self) -> None:
        data = _frame(186, b"\x18\x01", b"\x08\x02")

        packets = parse_frames(data)

        self.assertEqual(1, len(packets))
        packet = packets[0]
        self.assertEqual(0, packet.offset)
        self.assertEqual(len(data), packet.size)
        self.assertEqual(186, packet.cmd_id)
        self.assertEqual(2, packet.head_size)
        self.assertEqual(2, packet.body_size)
        self.assertEqual("1801", packet.head_hex)
        self.assertEqual("0802", packet.body_hex)

    def test_parse_frames_accepts_concatenated_frames(self) -> None:
        first = _frame(1)
        second = _frame(2, b"\x08\x01")

        packets = parse_frames(first + second)

        self.assertEqual([1, 2], [packet.cmd_id for packet in packets])
        self.assertEqual(len(first), packets[1].offset)

    def test_describe_frames_marks_watched_cmds(self) -> None:
        result = describe_frames(_frame(186) + _frame(200), [186])

        self.assertEqual(2, result["packet_count"])
        self.assertTrue(result["packets"][0]["watched"])
        self.assertFalse(result["packets"][1]["watched"])
        self.assertEqual("0xC", result["packets"][1]["offset"])

    def test_parse_hex_accepts_whitespace_and_prefixes(self) -> None:
        self.assertEqual(b"Eg", parse_hex("0x45 0x67"))

    def test_parse_hex_rejects_odd_digit_count(self) -> None:
        with self.assertRaisesRegex(ValueError, "odd number of digits"):
            parse_hex("456")

    def test_parse_frames_rejects_bad_tail(self) -> None:
        data = _frame(186)[:-2] + b"\x00\x00"

        with self.assertRaisesRegex(ValueError, "bad tail magic"):
            parse_frames(data)

    def test_parse_frames_rejects_truncated_frame(self) -> None:
        data = _frame(186, body=b"\x01\x02")[:-1]

        with self.assertRaisesRegex(ValueError, "truncated frame"):
            parse_frames(data)


if __name__ == "__main__":
    unittest.main()
