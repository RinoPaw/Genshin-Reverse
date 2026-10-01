from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from genshinre.registrygraph import build_registry_candidate_graph


class RegistryGraphTests(unittest.TestCase):
    def test_join_and_anchor_summary(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            usage = root / "usage-types.csv"
            getcmdid = root / "getcmdid.csv"
            output = root / "graph.csv"
            summary = root / "graph.summary.json"

            with usage.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=(
                        "usage_destination",
                        "type_slot_rva",
                        "source_encoding",
                        "encoded_usage_kind",
                        "type_index",
                        "type_definition_index",
                        "type_name",
                    ),
                )
                writer.writeheader()
                writer.writerows(
                    [
                        {
                            "usage_destination": "37523",
                            "type_slot_rva": "0x57E6498",
                            "source_encoding": "low29-encoded-index",
                            "encoded_usage_kind": "1",
                            "type_index": "405772",
                            "type_definition_index": "84249",
                            "type_name": "DMMJNICDOHM",
                        },
                        {
                            "usage_destination": "100",
                            "type_slot_rva": "0x57F6F60",
                            "source_encoding": "low29-encoded-index",
                            "encoded_usage_kind": "1",
                            "type_index": "500000",
                            "type_definition_index": "87483",
                            "type_name": "ONKOPMILDMF",
                        },
                        {
                            "usage_destination": "101",
                            "type_slot_rva": "0x5700000",
                            "source_encoding": "low29-encoded-index",
                            "encoded_usage_kind": "1",
                            "type_index": "500001",
                            "type_definition_index": "99999",
                            "type_name": "HJDNCHODGOL",
                        },
                    ]
                )

            with getcmdid.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=(
                        "cmd_id",
                        "type_name",
                        "type_definition_index",
                        "method_name",
                        "get_cmd_id_rva",
                    ),
                )
                writer.writeheader()
                writer.writerows(
                    [
                        {
                            "cmd_id": "9369",
                            "type_name": "DMMJNICDOHM",
                            "type_definition_index": "84249",
                            "method_name": "AEGNNPENLNM",
                            "get_cmd_id_rva": "0xC87EA60",
                        },
                        {
                            "cmd_id": "22899",
                            "type_name": "ONKOPMILDMF",
                            "type_definition_index": "87483",
                            "method_name": "X",
                            "get_cmd_id_rva": "0x1234",
                        },
                        {
                            "cmd_id": "26105",
                            "type_name": "HJDNCHODGOL",
                            "type_definition_index": "99999",
                            "method_name": "Y",
                            "get_cmd_id_rva": "0x10587260",
                        },
                    ]
                )

            result = build_registry_candidate_graph(usage, getcmdid, output, summary)
            self.assertEqual(3, result["unique_cmd_ids"])
            self.assertTrue(result["all_preserved_anchors_pass"])
            self.assertEqual(-4893, result["distance_from_historical_scale"])

            rows = list(csv.DictReader(output.open("r", encoding="utf-8", newline="")))
            self.assertEqual(3, len(rows))
            row9369 = next(row for row in rows if row["cmd_id"] == "9369")
            self.assertEqual("37523", row9369["usage_destination"])
            self.assertEqual("0x57E6498", row9369["type_slot_rva"])

            on_disk = json.loads(summary.read_text(encoding="utf-8"))
            self.assertTrue(on_disk["all_preserved_anchors_pass"])

    def test_multiple_usage_rows_are_retained_as_ambiguity(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            usage = root / "usage-types.csv"
            getcmdid = root / "getcmdid.csv"
            output = root / "graph.csv"

            with usage.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=("usage_destination", "type_slot_rva", "type_definition_index", "type_name"),
                )
                writer.writeheader()
                writer.writerows(
                    [
                        {"usage_destination": "1", "type_slot_rva": "0x1000", "type_definition_index": "7", "type_name": "AAA"},
                        {"usage_destination": "2", "type_slot_rva": "0x2000", "type_definition_index": "7", "type_name": "AAA"},
                    ]
                )

            with getcmdid.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=("cmd_id", "type_name", "type_definition_index", "get_cmd_id_rva"),
                )
                writer.writeheader()
                writer.writerow({"cmd_id": "123", "type_name": "AAA", "type_definition_index": "7", "get_cmd_id_rva": "0x3000"})

            result = build_registry_candidate_graph(usage, getcmdid, output)
            self.assertEqual(1, result["unique_cmd_ids"])
            self.assertEqual(1, result["ambiguous_getcmdid_candidates"])
            rows = list(csv.DictReader(output.open("r", encoding="utf-8", newline="")))
            self.assertEqual(2, len(rows))
            self.assertTrue(all(row["status"] == "JOINED_AMBIGUOUS_USAGE" for row in rows))


if __name__ == "__main__":
    unittest.main()
