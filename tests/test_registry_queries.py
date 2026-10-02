from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from genshinre.registry import query_registry


class RegistryQueryTests(unittest.TestCase):
    def _write_registry(self, path: Path) -> None:
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["index", "cmd_id", "type_name", "type_definition_index"],
            )
            writer.writeheader()
            writer.writerow(
                {
                    "index": "48",
                    "cmd_id": "186",
                    "type_name": "NLOMEGMJDGJ",
                    "type_definition_index": "61556",
                }
            )
            writer.writerow(
                {
                    "index": "2232",
                    "cmd_id": "9369",
                    "type_name": "DMMJNICDOHM",
                    "type_definition_index": "84249",
                }
            )

    def test_query_by_exact_numeric_identity(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "registry.csv"
            self._write_registry(path)

            rows = query_registry(path, type_definition_index=61556)
            self.assertEqual(1, len(rows))
            self.assertEqual("186", rows[0]["cmd_id"])

            rows = query_registry(path, registry_index=48)
            self.assertEqual(1, len(rows))
            self.assertEqual("NLOMEGMJDGJ", rows[0]["type_name"])

    def test_query_filters_can_be_combined(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "registry.csv"
            self._write_registry(path)

            rows = query_registry(
                path,
                cmd_id=186,
                type_name="nlomeg",
                type_definition_index=61556,
                registry_index=48,
            )
            self.assertEqual(1, len(rows))

            self.assertEqual([], query_registry(path, cmd_id=186, registry_index=2232))

    def test_query_requires_a_filter(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "registry.csv"
            self._write_registry(path)
            with self.assertRaisesRegex(ValueError, "at least one"):
                query_registry(path)


if __name__ == "__main__":
    unittest.main()
