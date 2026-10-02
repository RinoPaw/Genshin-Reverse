from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from genshinre.metadata import query_fields, query_methods


class MetadataQueryTests(unittest.TestCase):
    def test_query_methods_by_type_definition_index(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "methods.csv"
            with path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=[
                        "method_index",
                        "type_definition_index",
                        "type_name",
                        "method_name",
                        "rva",
                        "parameter_types",
                    ],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "method_index": "495472",
                        "type_definition_index": "61556",
                        "type_name": "NLOMEGMJDGJ",
                        "method_name": "IENGFLPCLNM",
                        "rva": "0x9ED2100",
                        "parameter_types": '["EIBJNHDPEMB"]',
                    }
                )
                writer.writerow(
                    {
                        "method_index": "696277",
                        "type_definition_index": "84249",
                        "type_name": "DMMJNICDOHM",
                        "method_name": "IENGFLPCLNM",
                        "rva": "0xC87E6A0",
                        "parameter_types": '["EIBJNHDPEMB"]',
                    }
                )

            rows = query_methods(path, type_definition_index=61556)
            self.assertEqual(1, len(rows))
            self.assertEqual("NLOMEGMJDGJ", rows[0]["type_name"])
            self.assertEqual(["EIBJNHDPEMB"], rows[0]["parameter_types"])

    def test_query_fields_combines_exact_indexes_and_text_filters(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "fields.csv"
            with path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=[
                        "field_index",
                        "type_definition_index",
                        "type_name",
                        "field_name",
                        "field_type",
                        "field_type_index",
                    ],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "field_index": "305829",
                        "type_definition_index": "61556",
                        "type_name": "NLOMEGMJDGJ",
                        "field_name": "DCCONFODELK",
                        "field_type": "kind_0x15",
                        "field_type_index": "476942",
                    }
                )
                writer.writerow(
                    {
                        "field_index": "305830",
                        "type_definition_index": "61556",
                        "type_name": "NLOMEGMJDGJ",
                        "field_name": "MGMOJNPMFFK",
                        "field_type": "kind_0x15",
                        "field_type_index": "476943",
                    }
                )

            rows = query_fields(
                path,
                type_name="nlomegmjdgj",
                type_definition_index=61556,
                field_type="KIND_0X15",
                field_type_index=476942,
            )
            self.assertEqual(1, len(rows))
            self.assertEqual("DCCONFODELK", rows[0]["field_name"])


if __name__ == "__main__":
    unittest.main()
