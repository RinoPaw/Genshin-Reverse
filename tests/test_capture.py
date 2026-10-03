from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from genshinre.capture import (
    PacketEvent,
    correlate_capture,
    decode_head_varints,
    load_packet_probe_capture,
    summarize_correlations,
)


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _head(field: int, value: int) -> str:
    return (_varint(field << 3) + _varint(value)).hex()


def _packet(index: int, direction: str, cmd_id: int, sequence: int | None) -> PacketEvent:
    payload = {"head_hex": "" if sequence is None else _head(3, sequence)}
    return PacketEvent(
        record_index=index,
        packet_index=index,
        timestamp_utc=None,
        direction=direction,
        cmd_id=cmd_id,
        payload=payload,
        sequence_value=sequence,
    )


def _transaction(verdict: str, mapped_cmd_id: int | None = None) -> dict[str, object]:
    return {
        "verdict": verdict,
        "mapped_cmd_id": mapped_cmd_id,
    }


class CaptureCorrelationTests(unittest.TestCase):
    def test_decode_head_varints_keeps_repeated_values(self) -> None:
        head = _head(3, 7) + _head(5, 99) + _head(3, 130)
        self.assertEqual({3: [7, 130], 5: [99]}, decode_head_varints(head))

    def test_load_capture_decodes_configured_sequence_field(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "capture.ndjson"
            rows = [
                {
                    "timestamp_utc": "2026-10-03T00:00:00+00:00",
                    "kind": "packet_probe",
                    "payload": {"ready": True, "hook": "control"},
                },
                {
                    "timestamp_utc": "2026-10-03T00:00:01+00:00",
                    "kind": "packet_probe",
                    "payload": {
                        "direction": "C2S",
                        "cmd_id": 9369,
                        "head_hex": _head(3, 321),
                    },
                },
            ]
            path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

            packets, ready = load_packet_probe_capture(path, sequence_field=3)

            self.assertEqual(1, len(ready))
            self.assertEqual(1, len(packets))
            self.assertEqual(321, packets[0].sequence_value)
            self.assertEqual(9369, packets[0].cmd_id)

    def test_unique_same_sequence_candidate_is_promotable(self) -> None:
        packets = [
            _packet(0, "C2S", 9369, 42),
            _packet(1, "S2C", 36641, 41),
            _packet(2, "S2C", 20290, 42),
        ]

        result = correlate_capture(
            packets,
            request_cmd=9369,
            candidate_cmds=[36641, 20290],
        )

        self.assertEqual(1, len(result))
        self.assertEqual("promotable", result[0]["verdict"])
        self.assertEqual(20290, result[0]["mapped_cmd_id"])
        self.assertEqual([20290], [row["cmd_id"] for row in result[0]["same_sequence_candidates"]])

    def test_next_request_closes_previous_window(self) -> None:
        packets = [
            _packet(0, "C2S", 9369, 10),
            _packet(1, "S2C", 100, 10),
            _packet(2, "C2S", 9369, 11),
            _packet(3, "S2C", 36641, 10),
            _packet(4, "S2C", 20290, 11),
        ]

        result = correlate_capture(
            packets,
            request_cmd=9369,
            candidate_cmds=[36641, 20290],
            after_events=10,
        )

        self.assertEqual("no-candidate", result[0]["verdict"])
        self.assertEqual("promotable", result[1]["verdict"])
        self.assertEqual(20290, result[1]["mapped_cmd_id"])

    def test_single_candidate_without_sequence_is_not_promotable(self) -> None:
        packets = [
            _packet(0, "C2S", 9369, None),
            _packet(1, "S2C", 36641, None),
        ]

        result = correlate_capture(
            packets,
            request_cmd=9369,
            candidate_cmds=[36641, 20290],
        )[0]

        self.assertEqual("candidate-observed-no-sequence", result["verdict"])
        self.assertEqual(36641, result["mapped_cmd_id"])

    def test_summary_requires_all_transactions_to_promote_same_candidate(self) -> None:
        result = summarize_correlations(
            [
                _transaction("promotable", 20290),
                _transaction("promotable", 20290),
            ]
        )

        self.assertEqual("promotable-consistent", result["verdict"])
        self.assertEqual(20290, result["mapped_cmd_id"])
        self.assertEqual(2, result["promotable_transaction_count"])
        self.assertEqual([20290], result["promotable_cmd_ids"])

    def test_summary_rejects_conflicting_promotions(self) -> None:
        result = summarize_correlations(
            [
                _transaction("promotable", 36641),
                _transaction("promotable", 20290),
            ]
        )

        self.assertEqual("contradictory", result["verdict"])
        self.assertIsNone(result["mapped_cmd_id"])
        self.assertEqual([20290, 36641], result["promotable_cmd_ids"])

    def test_summary_marks_mixed_evidence_partial(self) -> None:
        result = summarize_correlations(
            [
                _transaction("promotable", 36641),
                _transaction("no-candidate"),
            ]
        )

        self.assertEqual("partial-consistent", result["verdict"])
        self.assertIsNone(result["mapped_cmd_id"])
        self.assertEqual(
            {"no-candidate": 1, "promotable": 1},
            result["verdict_counts"],
        )

    def test_summary_handles_capture_without_request(self) -> None:
        result = summarize_correlations([])

        self.assertEqual("no-request", result["verdict"])
        self.assertIsNone(result["mapped_cmd_id"])
        self.assertEqual(0, result["transaction_count"])


if __name__ == "__main__":
    unittest.main()
