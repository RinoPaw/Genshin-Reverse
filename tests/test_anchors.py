from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from genshinre.anchors import verify_metadata_anchors


class MetadataAnchorTests(unittest.TestCase):
    def _write_csv(self, path: Path, fieldnames: tuple[str, ...], rows: list[dict[str, str]]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    def test_streams_all_anchor_kinds(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            metadata = root / "metadata"
            self._write_csv(
                metadata / "types.csv",
                ("type_definition_index", "type_name", "field_start", "field_count", "method_start", "method_count", "type_cache_rva"),
                [
                    {
                        "type_definition_index": "42",
                        "type_name": "TYPE",
                        "field_start": "10",
                        "field_count": "2",
                        "method_start": "20",
                        "method_count": "1",
                        "type_cache_rva": "0x1000",
                    }
                ],
            )
            self._write_csv(
                metadata / "fields.csv",
                ("field_index", "type_definition_index", "type_name", "field_name", "field_type", "field_type_index"),
                [
                    {
                        "field_index": "10",
                        "type_definition_index": "42",
                        "type_name": "TYPE",
                        "field_name": "FIELD",
                        "field_type": "uint32",
                        "field_type_index": "7",
                    }
                ],
            )
            self._write_csv(
                metadata / "methods.csv",
                ("method_index", "type_definition_index", "type_name", "method_name", "rva", "parameter_types", "parameter_start", "parameter_count"),
                [
                    {
                        "method_index": "20",
                        "type_definition_index": "42",
                        "type_name": "TYPE",
                        "method_name": "METHOD",
                        "rva": "0x2000",
                        "parameter_types": '["REQ","uint32"]',
                        "parameter_start": "30",
                        "parameter_count": "2",
                    },
                    {
                        "method_index": "21",
                        "type_definition_index": "43",
                        "type_name": "OTHER",
                        "method_name": "LEGACY_PARAMS",
                        "rva": "0x3000",
                        "parameter_types": "REQ|int32",
                        "parameter_start": "32",
                        "parameter_count": "2",
                    },
                ],
            )
            anchors = root / "anchors.json"
            anchors.write_text(
                json.dumps(
                    {
                        "types": [
                            {
                                "type_name": "TYPE",
                                "type_definition_index": 42,
                                "type_cache_rva": "0x1000",
                            }
                        ],
                        "fields": [
                            {
                                "field_index": 10,
                                "type_definition_index": 42,
                                "field_name": "FIELD",
                                "field_type": "uint32",
                            }
                        ],
                        "methods": [
                            {
                                "method_index": 20,
                                "rva": "0x2000",
                                "parameter_types": ["REQ", "uint32"],
                            },
                            {
                                "rva": "0x3000",
                                "parameter_types": ["REQ"],
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = verify_metadata_anchors(metadata, anchors)
            self.assertTrue(result["passed"])
            self.assertEqual(result["check_count"], 4)
            self.assertEqual(result["failed_count"], 0)
            self.assertTrue(all(check["match_count"] == 1 for check in result["checks"]))

    def test_missing_anchor_fails_without_loading_tables_into_result(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            metadata = root / "metadata"
            self._write_csv(
                metadata / "types.csv",
                ("type_definition_index", "type_name"),
                [{"type_definition_index": "1", "type_name": "ONE"}],
            )
            self._write_csv(metadata / "methods.csv", ("method_index", "rva", "parameter_types"), [])
            anchors = root / "anchors.json"
            anchors.write_text(
                json.dumps({"types": [{"type_name": "MISSING"}], "methods": []}),
                encoding="utf-8",
            )

            result = verify_metadata_anchors(metadata, anchors)
            self.assertFalse(result["passed"])
            self.assertEqual(result["failed_count"], 1)
            self.assertEqual(result["checks"][0]["match_count"], 0)


if __name__ == "__main__":
    unittest.main()
