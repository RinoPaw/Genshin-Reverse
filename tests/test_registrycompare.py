from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from genshinre.registrycompare import compare_raw_registries


class RegistryCompareTests(unittest.TestCase):
    def _write(self, path: Path, fieldnames: tuple[str, ...], rows: list[dict[str, object]]) -> None:
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    def test_detects_cmd_flag_and_slot_agreement(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            direct = root / "direct.csv"
            usage = root / "usage.csv"
            self._write(
                direct,
                ("index", "cmd_id", "registry_flag", "type_slot_rva"),
                [
                    {"index": 0, "cmd_id": 10, "registry_flag": 1, "type_slot_rva": "0x1000"},
                    {"index": 1, "cmd_id": 20, "registry_flag": 0, "type_slot_rva": "0x2000"},
                    {"index": 2, "cmd_id": 30, "registry_flag": 1, "type_slot_rva": "0x3000"},
                ],
            )
            self._write(
                usage,
                ("index", "cmd_id", "registry_flag", "usage_destination", "type_slot_rvas", "type_name"),
                [
                    {"index": 0, "cmd_id": 10, "registry_flag": 1, "usage_destination": 100, "type_slot_rvas": "0x1000|0x1010", "type_name": "A"},
                    {"index": 1, "cmd_id": 20, "registry_flag": 0, "usage_destination": 200, "type_slot_rvas": "0x2000", "type_name": "B"},
                    {"index": 2, "cmd_id": 31, "registry_flag": 1, "usage_destination": 300, "type_slot_rvas": "0x3000", "type_name": "C"},
                ],
            )
            result = compare_raw_registries(direct, usage)
            self.assertEqual(3, result["compared_rows"])
            self.assertEqual(2, result["cmd_matches"])
            self.assertEqual(3, result["flag_matches"])
            self.assertEqual(3, result["slot_matches"])
            self.assertEqual(2, result["complete_matches"])
            self.assertEqual(1, result["mismatch_count"])
            self.assertFalse(result["full_agreement"])
            self.assertEqual(2, result["mismatches"][0]["index"])

    def test_missing_index_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            direct = root / "direct.csv"
            usage = root / "usage.csv"
            self._write(
                direct,
                ("index", "cmd_id", "registry_flag", "type_slot_rva"),
                [{"index": 0, "cmd_id": 10, "registry_flag": 1, "type_slot_rva": "0x1000"}],
            )
            self._write(
                usage,
                ("index", "cmd_id", "registry_flag", "type_slot_rvas"),
                [{"index": 1, "cmd_id": 20, "registry_flag": 0, "type_slot_rvas": "0x2000"}],
            )
            result = compare_raw_registries(direct, usage)
            self.assertEqual([1], result["missing_direct_indices"])
            self.assertEqual([0], result["missing_usage_indices"])
            self.assertEqual(0, result["compared_rows"])


if __name__ == "__main__":
    unittest.main()
