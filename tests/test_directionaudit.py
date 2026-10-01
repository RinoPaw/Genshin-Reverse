from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from genshinre.directionaudit import audit_direction_flags


class DirectionAuditTests(unittest.TestCase):
    def _write(self, path: Path, fieldnames: tuple[str, ...], rows: list[dict[str, object]]) -> None:
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    def test_perfect_req_rsp_controls_validate_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            raw = root / "raw.csv"
            known = root / "known.csv"

            self._write(
                raw,
                ("cmd_id", "registry_flag"),
                [
                    {"cmd_id": 10, "registry_flag": 1},
                    {"cmd_id": 11, "registry_flag": 0},
                    {"cmd_id": 20, "registry_flag": 1},
                    {"cmd_id": 21, "registry_flag": 0},
                    {"cmd_id": 30, "registry_flag": 0},
                ],
            )
            self._write(
                known,
                ("semantic_name", "cmd_id"),
                [
                    {"semantic_name": "FooReq", "cmd_id": 10},
                    {"semantic_name": "FooRsp", "cmd_id": 11},
                    {"semantic_name": "BarReq", "cmd_id": 20},
                    {"semantic_name": "BarRsp", "cmd_id": 21},
                    # Notify is deliberately excluded from directional controls.
                    {"semantic_name": "SomethingNotify", "cmd_id": 30},
                ],
            )

            result = audit_direction_flags(raw, known)
            self.assertEqual(2, result["req_controls"])
            self.assertEqual(2, result["req_flag1_matches"])
            self.assertEqual(2, result["rsp_controls"])
            self.assertEqual(2, result["rsp_flag0_matches"])
            self.assertEqual(2, result["req_rsp_pairs"])
            self.assertEqual(2, result["req_rsp_pairs_consistent"])
            self.assertTrue(result["perfect_req_rsp_suffix_agreement"])
            self.assertTrue(result["perfect_req_rsp_pair_agreement"])
            self.assertEqual("direction-mapping-strongly-validated", result["status"])

    def test_mismatch_remains_audit_needed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            raw = root / "raw.csv"
            known = root / "known.csv"

            self._write(
                raw,
                ("cmd_id", "registry_flag"),
                [
                    {"cmd_id": 10, "registry_flag": 0},
                    {"cmd_id": 11, "registry_flag": 0},
                ],
            )
            self._write(
                known,
                ("semantic_name", "cmd_id"),
                [
                    {"semantic_name": "FooReq", "cmd_id": 10},
                    {"semantic_name": "FooRsp", "cmd_id": 11},
                ],
            )

            result = audit_direction_flags(raw, known)
            self.assertFalse(result["perfect_req_rsp_suffix_agreement"])
            self.assertFalse(result["perfect_req_rsp_pair_agreement"])
            self.assertEqual(1, result["suffix_mismatch_count"])
            self.assertEqual("FooReq", result["suffix_mismatches"][0]["semantic_name"])
            self.assertEqual(1, result["pair_mismatch_count"])
            self.assertEqual("direction-mapping-audit-needed", result["status"])

    def test_notify_only_data_cannot_validate_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            raw = root / "raw.csv"
            known = root / "known.csv"

            self._write(
                raw,
                ("cmd_id", "registry_flag"),
                [{"cmd_id": 30, "registry_flag": 1}],
            )
            self._write(
                known,
                ("semantic_name", "cmd_id"),
                [{"semantic_name": "FooNotify", "cmd_id": 30}],
            )

            result = audit_direction_flags(raw, known)
            self.assertEqual(0, result["req_controls"])
            self.assertEqual(0, result["rsp_controls"])
            self.assertEqual(0, result["req_rsp_pairs"])
            self.assertFalse(result["perfect_req_rsp_suffix_agreement"])
            self.assertFalse(result["perfect_req_rsp_pair_agreement"])
            self.assertEqual("direction-mapping-audit-needed", result["status"])


if __name__ == "__main__":
    unittest.main()
