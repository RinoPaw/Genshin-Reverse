from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from genshinre.registryreport import generate_registry_candidate_report


GRAPH_FIELDS = (
    "cmd_id",
    "type_name",
    "type_definition_index",
    "get_cmd_id_rva",
    "usage_destination",
    "type_slot_rva",
    "source_encoding",
    "encoded_usage_kind",
    "status",
    "evidence",
)


class RegistryReportTests(unittest.TestCase):
    def _write_graph(self, path: Path) -> None:
        rows = [
            {
                "cmd_id": "186",
                "type_name": "UNKNOWN186TYPE",
                "type_definition_index": "70000",
                "get_cmd_id_rva": "0x1000",
                "usage_destination": "200",
                "type_slot_rva": "0x5800000",
                "source_encoding": "low29-encoded-index",
                "encoded_usage_kind": "1",
                "status": "JOINED_UNIQUE",
                "evidence": "fixture",
            },
            {
                "cmd_id": "9369",
                "type_name": "DMMJNICDOHM",
                "type_definition_index": "84249",
                "get_cmd_id_rva": "0xC87EA60",
                "usage_destination": "37523",
                "type_slot_rva": "0x57E6498",
                "source_encoding": "low29-encoded-index",
                "encoded_usage_kind": "1",
                "status": "JOINED_UNIQUE",
                "evidence": "fixture",
            },
            {
                "cmd_id": "22899",
                "type_name": "ONKOPMILDMF",
                "type_definition_index": "87483",
                "get_cmd_id_rva": "0x2000",
                "usage_destination": "300",
                "type_slot_rva": "0x57F6F60",
                "source_encoding": "low29-encoded-index",
                "encoded_usage_kind": "1",
                "status": "JOINED_AMBIGUOUS_USAGE",
                "evidence": "fixture",
            },
            {
                "cmd_id": "22899",
                "type_name": "ONKOPMILDMF",
                "type_definition_index": "87483",
                "get_cmd_id_rva": "0x2000",
                "usage_destination": "301",
                "type_slot_rva": "0x57F7000",
                "source_encoding": "low29-encoded-index",
                "encoded_usage_kind": "1",
                "status": "JOINED_AMBIGUOUS_USAGE",
                "evidence": "fixture",
            },
            {
                "cmd_id": "26105",
                "type_name": "HJDNCHODGOL",
                "type_definition_index": "99999",
                "get_cmd_id_rva": "0x10587260",
                "usage_destination": "400",
                "type_slot_rva": "0x5700000",
                "source_encoding": "low29-encoded-index",
                "encoded_usage_kind": "1",
                "status": "JOINED_UNIQUE",
                "evidence": "fixture",
            },
        ]
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=GRAPH_FIELDS)
            writer.writeheader()
            writer.writerows(rows)

    def test_report_focus_ambiguity_and_control_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            graph = root / "graph.csv"
            summary = root / "summary.json"
            known = root / "known.csv"
            report = root / "report.md"
            self._write_graph(graph)

            summary.write_text(
                json.dumps(
                    {
                        "historical_registry_scale": 4896,
                        "distance_from_historical_scale": -4892,
                        "all_preserved_anchors_pass": True,
                        "anchors": [
                            {
                                "cmd_id": 9369,
                                "passed": True,
                                "checks": {"type_name": True, "type_slot_rva": True},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with known.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=("semantic_name", "cmd_id"))
                writer.writeheader()
                writer.writerows(
                    [
                        {"semantic_name": "Unknown186", "cmd_id": "186"},
                        {"semantic_name": "UnlockTransPointReq", "cmd_id": "9369"},
                        {"semantic_name": "Missing", "cmd_id": "555"},
                    ]
                )

            result = generate_registry_candidate_report(
                graph,
                summary,
                report,
                known_opcodes_csv=known,
            )
            self.assertEqual(4, result["unique_cmd_ids"])
            self.assertEqual(3, result["joined_unique_cmd_ids"])
            self.assertEqual(1, result["ambiguous_usage_cmd_ids"])
            self.assertEqual(1, result["duplicate_cmd_ids"])
            self.assertTrue(result["all_preserved_anchors_pass"])
            self.assertEqual(1, result["control_set"]["missing_count"])

            text = report.read_text(encoding="utf-8")
            self.assertIn("### 186", text)
            self.assertIn("UNKNOWN186TYPE", text)
            self.assertIn("### 9369", text)
            self.assertIn("Usage ambiguity", text)
            self.assertIn("AstaPS control-set coverage", text)
            self.assertIn("Missing preview: `555`", text)

    def test_report_without_control_set(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            graph = root / "graph.csv"
            summary = root / "summary.json"
            report = root / "report.md"
            self._write_graph(graph)
            summary.write_text(
                json.dumps(
                    {
                        "historical_registry_scale": 4896,
                        "distance_from_historical_scale": -4892,
                        "all_preserved_anchors_pass": False,
                        "anchors": [],
                    }
                ),
                encoding="utf-8",
            )

            result = generate_registry_candidate_report(graph, summary, report)
            self.assertIsNone(result["control_set"])
            text = report.read_text(encoding="utf-8")
            self.assertNotIn("AstaPS control-set coverage", text)
            self.assertIn("### 186", text)


if __name__ == "__main__":
    unittest.main()
