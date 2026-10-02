from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ANALYZER = ROOT / "tools/analyze_unlock_trans_point_capture_71.py"
EXPECTED_EXE_SHA256 = "08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d"


def frame(cmd_id: int) -> bytes:
    return (
        b"\x45\x67"
        + cmd_id.to_bytes(2, "big")
        + b"\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x89\xAB"
    )


def packet_row(timestamp: datetime, direction: str, cmd_id: int) -> dict[str, object]:
    raw = frame(cmd_id)
    return {
        "timestamp_utc": timestamp.isoformat(),
        "kind": "packet_probe",
        "payload": {
            "direction": direction,
            "cmd_id": cmd_id,
            "frame_size": len(raw),
            "head_size": 0,
            "body_size": 0,
            "head_hex": "",
            "watched": cmd_id in {9369, 36641, 20290, 25567},
            "frame_hex": raw.hex(),
        },
    }


def capture_session_row(timestamp: datetime, exe_sha256: str = EXPECTED_EXE_SHA256) -> dict[str, object]:
    return {
        "timestamp_utc": timestamp.isoformat(),
        "kind": "capture_session",
        "payload": {
            "process": "GenshinImpact.exe",
            "exe": r"D:\Genshin Impact\GenshinImpact.exe",
            "exe_sha256": exe_sha256,
            "expected_exe_sha256": EXPECTED_EXE_SHA256,
            "build_verified": exe_sha256 == EXPECTED_EXE_SHA256,
            "script": "capture_game_packets_71.js",
        },
    }


def ready_row(timestamp: datetime) -> dict[str, object]:
    return {
        "timestamp_utc": timestamp.isoformat(),
        "kind": "packet_probe",
        "payload": {
            "ready": True,
            "module": "GenshinImpact.exe",
            "module_base": "0x7ff600000000",
            "s2c_post_xor_rva": "0xA01846A",
            "c2s_pre_xor_rva": "0xA01A0EF",
            "watched_cmd_ids": [9369, 36641, 20290, 25567],
        },
    }


def maintained_capture(packet_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    base = datetime(2026, 10, 2, 11, 59, 58, tzinfo=timezone.utc)
    return [capture_session_row(base), ready_row(base + timedelta(seconds=1)), *packet_rows]


def run_analyzer(rows: list[dict[str, object]], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "capture.ndjson"
        path.write_text(
            "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows),
            encoding="utf-8",
        )
        return subprocess.run(
            [sys.executable, str(ANALYZER), str(path)],
            cwd=ROOT,
            check=check,
            capture_output=True,
            text=True,
        )


def analyze(packet_rows: list[dict[str, object]]) -> dict[str, object]:
    return json.loads(run_analyzer(maintained_capture(packet_rows)).stdout)


class UnlockTransPointCaptureTests(unittest.TestCase):
    def test_unique_candidate_36641(self) -> None:
        t0 = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
        result = analyze(
            [
                packet_row(t0, "C2S", 9369),
                packet_row(t0 + timedelta(milliseconds=80), "S2C", 25567),
                packet_row(t0 + timedelta(milliseconds=120), "S2C", 36641),
            ]
        )
        self.assertTrue(result["capture_provenance"]["verified"])
        self.assertEqual(EXPECTED_EXE_SHA256, result["capture_provenance"]["exe_sha256"])
        self.assertEqual(1, result["unlock_request_count"])
        tx = result["transactions"][0]
        self.assertEqual("unique_candidate_observed", tx["verdict"])
        self.assertEqual([36641], tx["candidate_cmd_ids"])
        self.assertTrue(tx["scene_point_unlock_notify_seen"])

    def test_unique_candidate_20290(self) -> None:
        t0 = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
        result = analyze(
            [
                packet_row(t0, "C2S", 9369),
                packet_row(t0 + timedelta(milliseconds=100), "S2C", 20290),
            ]
        )
        tx = result["transactions"][0]
        self.assertEqual("unique_candidate_observed", tx["verdict"])
        self.assertEqual([20290], tx["candidate_cmd_ids"])
        self.assertFalse(tx["scene_point_unlock_notify_seen"])

    def test_both_candidates_remain_ambiguous(self) -> None:
        t0 = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
        result = analyze(
            [
                packet_row(t0, "C2S", 9369),
                packet_row(t0 + timedelta(milliseconds=100), "S2C", 36641),
                packet_row(t0 + timedelta(milliseconds=150), "S2C", 20290),
            ]
        )
        tx = result["transactions"][0]
        self.assertEqual("ambiguous_both_candidates_observed", tx["verdict"])
        self.assertEqual([20290, 36641], tx["candidate_cmd_ids"])

    def test_next_unlock_request_starts_a_new_transaction(self) -> None:
        t0 = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
        result = analyze(
            [
                packet_row(t0, "C2S", 9369),
                packet_row(t0 + timedelta(milliseconds=50), "S2C", 36641),
                packet_row(t0 + timedelta(seconds=1), "C2S", 9369),
                packet_row(t0 + timedelta(seconds=1, milliseconds=60), "S2C", 20290),
            ]
        )
        self.assertEqual(2, result["unlock_request_count"])
        self.assertEqual([36641], result["transactions"][0]["candidate_cmd_ids"])
        self.assertEqual([20290], result["transactions"][1]["candidate_cmd_ids"])

    def test_corrupt_preserved_frame_is_rejected(self) -> None:
        t0 = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
        row = packet_row(t0, "C2S", 9369)
        row["payload"]["frame_hex"] = frame(36641).hex()
        completed = run_analyzer(maintained_capture([row]), check=False)
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("framed CmdId", completed.stderr)

    def test_missing_capture_session_is_rejected(self) -> None:
        t0 = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
        completed = run_analyzer(
            [ready_row(t0), packet_row(t0 + timedelta(milliseconds=20), "C2S", 9369)],
            check=False,
        )
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("exactly one capture_session", completed.stderr)

    def test_wrong_build_hash_is_rejected(self) -> None:
        t0 = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
        rows = [
            capture_session_row(t0, exe_sha256="00" * 32),
            ready_row(t0 + timedelta(milliseconds=10)),
            packet_row(t0 + timedelta(milliseconds=20), "C2S", 9369),
        ]
        completed = run_analyzer(rows, check=False)
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("does not prove the pinned global 7.1 executable", completed.stderr)


if __name__ == "__main__":
    unittest.main()
