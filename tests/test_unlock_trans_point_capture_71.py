from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/runtime/analyze_unlock_trans_point_capture_71.py"
SPEC = importlib.util.spec_from_file_location("unlock_capture_71", TOOL)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class UnlockTransPointCapture71Tests(unittest.TestCase):
    def packet(
        self,
        packet_index: int,
        direction: str,
        cmd_id: int,
        sequence: int | None,
    ):
        head_hex = "" if sequence is None else bytes([0x18, sequence]).hex()
        payload = {
            "direction": direction,
            "cmd_id": cmd_id,
            "head_hex": head_hex,
            "head_size": len(bytes.fromhex(head_hex)),
            "body_size": 0,
            "frame_size": 12 + len(bytes.fromhex(head_hex)),
        }
        return MODULE.PacketEvent(
            record_index=packet_index,
            packet_index=packet_index,
            timestamp_utc=None,
            direction=direction,
            cmd_id=cmd_id,
            payload=payload,
            client_sequence_id=MODULE.client_sequence_id(payload),
        )

    def test_decodes_packet_head_client_sequence_id(self) -> None:
        # field 3, varint 150 -> 0x18 0x96 0x01
        fields = MODULE.decode_packet_head_varints("189601")
        self.assertEqual([150], fields[3])

    def test_promotes_unique_candidate_with_matching_sequence(self) -> None:
        packets = [
            self.packet(0, "C2S", 9369, 7),
            self.packet(1, "S2C", 25567, 0),
            self.packet(2, "S2C", 20290, 7),
        ]
        result = MODULE.analyze_transaction(packets, 0, 24)
        self.assertEqual("promotable", result["verdict"])
        self.assertEqual(20290, result["mapped_cmd_id"])

    def test_does_not_promote_candidate_with_wrong_sequence(self) -> None:
        packets = [
            self.packet(0, "C2S", 9369, 7),
            self.packet(1, "S2C", 36641, 8),
        ]
        result = MODULE.analyze_transaction(packets, 0, 24)
        self.assertEqual("candidate-observed-sequence-mismatch", result["verdict"])
        self.assertEqual(36641, result["mapped_cmd_id"])

    def test_ambiguous_when_both_candidates_match_sequence(self) -> None:
        packets = [
            self.packet(0, "C2S", 9369, 7),
            self.packet(1, "S2C", 36641, 7),
            self.packet(2, "S2C", 20290, 7),
        ]
        result = MODULE.analyze_transaction(packets, 0, 24)
        self.assertEqual("ambiguous", result["verdict"])
        self.assertIsNone(result["mapped_cmd_id"])


if __name__ == "__main__":
    unittest.main()
