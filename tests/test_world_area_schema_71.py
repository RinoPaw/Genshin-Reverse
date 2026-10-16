from __future__ import annotations

import csv
import importlib.util
from pathlib import Path
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "scripts/probe-7.1-world-area-schema.py"
spec = importlib.util.spec_from_file_location("world_area_schema_probe_71", SOURCE)
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


class WorldAreaSchemaProbeTests(unittest.TestCase):
    def test_owner_join_and_missing_token_retention(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root)
            fields = p / "fields.csv"
            methods = p / "methods.csv"
            with fields.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f, fieldnames=("field_index", "field_name", "field_type",
                                   "type_name", "type_definition_index")
                )
                writer.writeheader()
                writer.writerow({
                    "field_index": 4, "field_name": "OBKNAJCIHEA",
                    "field_type": "List", "type_name": "ROOT_TYPE",
                    "type_definition_index": 10,
                })
                writer.writerow({
                    "field_index": 5, "field_name": "not_relevant",
                    "field_type": "int32", "type_name": "ROOT_TYPE",
                    "type_definition_index": 10,
                })
                writer.writerow({
                    "field_index": 6, "field_name": "BFLLDPOAJGD",
                    "field_type": "List", "type_name": "SHAPE_TYPE",
                    "type_definition_index": 11,
                })
            with methods.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f, fieldnames=("method_index", "method_name", "rva",
                                   "parameter_types", "type_name",
                                   "type_definition_index")
                )
                writer.writeheader()
                writer.writerow({
                    "method_index": 10, "method_name": "GMENPOPMKAA",
                    "rva": "0xABC", "parameter_types": '["FNIAHJGHFAK"]',
                    "type_name": "ROOT_TYPE", "type_definition_index": 10,
                })
                writer.writerow({
                    "method_index": 11, "method_name": "Irrelevant",
                    "rva": "0xDEF", "parameter_types": "[]",
                    "type_name": "OTHER_TYPE", "type_definition_index": 13,
                })
            report = scan.locate(fields, methods)
            self.assertEqual(2, report["matchingOwnerCount"])
            self.assertIn("OPHHFKKPLDI", report["unmatchedTokens"])
            self.assertEqual("0xABC", report["methodsByOwner"]["ROOT_TYPE"][0]["rva"])
            self.assertEqual(["OBKNAJCIHEA", "not_relevant"],
                             [x["name"] for x in report["fieldsByOwner"]["ROOT_TYPE"]])
            self.assertNotIn("OTHER_TYPE", report["methodsByOwner"])


if __name__ == "__main__":
    unittest.main()
