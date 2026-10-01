from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from genshinre.graphdiag import diagnose_candidate_graph


class GraphDiagnosticTests(unittest.TestCase):
    def test_coverage_missing_graph_only_and_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            graph = root / "graph.csv"
            known = root / "known.csv"
            output = root / "diag.json"

            with graph.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=("cmd_id", "type_name"))
                writer.writeheader()
                writer.writerows(
                    [
                        {"cmd_id": "1", "type_name": "A"},
                        {"cmd_id": "2", "type_name": "B"},
                        {"cmd_id": "3", "type_name": "C"},
                        {"cmd_id": "3", "type_name": "C2"},
                    ]
                )

            with known.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=("semantic_name", "cmd_id"))
                writer.writeheader()
                writer.writerows(
                    [
                        {"semantic_name": "One", "cmd_id": "1"},
                        {"semantic_name": "Two", "cmd_id": "2"},
                        {"semantic_name": "Four", "cmd_id": "4"},
                    ]
                )

            result = diagnose_candidate_graph(graph, known, output)
            self.assertEqual(3, result["graph_unique_cmd_ids"])
            self.assertEqual({"3": 2}, result["graph_duplicate_cmd_ids"])
            self.assertEqual(2, result["control_matched"])
            self.assertEqual([4], result["control_missing_cmd_ids"])
            self.assertEqual([3], result["graph_only_cmd_ids"])
            self.assertAlmostEqual(2 / 3, result["control_coverage"])
            self.assertFalse(result["all_control_ids_present"])
            self.assertEqual(result, json.loads(output.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
