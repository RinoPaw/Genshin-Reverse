from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from genshinre.registryselect import OUTPUT_COLUMNS, refine_registry_candidates


class RegistrySelectTests(unittest.TestCase):
    def test_conservative_one_to_one_selection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            graph = root / "graph.csv"
            output = root / "strict.csv"

            fields = (
                "cmd_id",
                "type_name",
                "type_definition_index",
                "get_cmd_id_rva",
                "usage_destination",
                "type_slot_rva",
                "source_encoding",
                "encoded_usage_kind",
            )
            rows = [
                {"cmd_id": "1", "type_name": "A", "type_definition_index": "1", "get_cmd_id_rva": "0x100", "usage_destination": "10", "type_slot_rva": "0x1000", "source_encoding": "low29-encoded-index", "encoded_usage_kind": "1"},
                {"cmd_id": "2", "type_name": "B", "type_definition_index": "2", "get_cmd_id_rva": "0x200", "usage_destination": "20", "type_slot_rva": "0x2000", "source_encoding": "low29-encoded-index", "encoded_usage_kind": "1"},
                {"cmd_id": "3", "type_name": "B", "type_definition_index": "2", "get_cmd_id_rva": "0x210", "usage_destination": "20", "type_slot_rva": "0x2000", "source_encoding": "low29-encoded-index", "encoded_usage_kind": "1"},
                {"cmd_id": "4", "type_name": "C", "type_definition_index": "3", "get_cmd_id_rva": "0x300", "usage_destination": "30", "type_slot_rva": "0x3000", "source_encoding": "low29-encoded-index", "encoded_usage_kind": "1"},
                {"cmd_id": "4", "type_name": "D", "type_definition_index": "4", "get_cmd_id_rva": "0x400", "usage_destination": "40", "type_slot_rva": "0x4000", "source_encoding": "low29-encoded-index", "encoded_usage_kind": "1"},
                {"cmd_id": "5", "type_name": "E", "type_definition_index": "5", "get_cmd_id_rva": "0x500", "usage_destination": "50", "type_slot_rva": "0x5000", "source_encoding": "low29-encoded-index", "encoded_usage_kind": "1"},
                {"cmd_id": "5", "type_name": "E", "type_definition_index": "5", "get_cmd_id_rva": "0x500", "usage_destination": "51", "type_slot_rva": "0x5008", "source_encoding": "low29-encoded-index", "encoded_usage_kind": "1"},
                {"cmd_id": "6", "type_name": "F", "type_definition_index": "6", "get_cmd_id_rva": "0x600", "usage_destination": "60", "type_slot_rva": "0x6000", "source_encoding": "low29-encoded-index", "encoded_usage_kind": "1"},
            ]
            with graph.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                writer.writerows(rows)

            summary = refine_registry_candidates(graph, output)
            self.assertEqual(2, summary["selected_unique_cmd_ids"])
            self.assertEqual(1, summary["rejection_counts"]["type_has_multiple_cmd_ids"])
            self.assertEqual(2, summary["rejection_counts"]["cmd_id_maps_multiple_types"])
            self.assertEqual(1, summary["rejection_counts"]["type_slot_not_unique"])

            with output.open("r", encoding="utf-8", newline="") as f:
                selected = list(csv.DictReader(f))
            self.assertEqual(list(OUTPUT_COLUMNS), list(selected[0].keys()))
            self.assertEqual(["1", "6"], [row["cmd_id"] for row in selected])
            self.assertTrue(all(row["status"] == "STATIC_CANDIDATE" for row in selected))


if __name__ == "__main__":
    unittest.main()
