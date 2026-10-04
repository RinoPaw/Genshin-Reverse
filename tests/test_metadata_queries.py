from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from genshinre.metadata import query_fields, query_method_references, query_methods


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

            rows = query_methods(path, rva=0x9ED2100)
            self.assertEqual(1, len(rows))
            self.assertEqual("NLOMEGMJDGJ", rows[0]["type_name"])
            self.assertEqual("IENGFLPCLNM", rows[0]["method_name"])

    def test_query_method_references_tracks_external_signature_edges(self) -> None:
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
                        "return_type",
                        "parameter_types",
                    ],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "method_index": "1",
                        "type_definition_index": "10",
                        "type_name": "TARGETTYPE",
                        "method_name": "CopyFrom",
                        "rva": "0x1000",
                        "return_type": "",
                        "parameter_types": '["TARGETTYPE"]',
                    }
                )
                writer.writerow(
                    {
                        "method_index": "2",
                        "type_definition_index": "20",
                        "type_name": "OWNER",
                        "method_name": "Handle",
                        "rva": "0x2000",
                        "return_type": "System.Collections.Generic.List<TARGETTYPE>",
                        "parameter_types": '["TARGETTYPE", "uint32"]',
                    }
                )
                writer.writerow(
                    {
                        "method_index": "3",
                        "type_definition_index": "30",
                        "type_name": "OTHER",
                        "method_name": "FalsePositive",
                        "rva": "0x3000",
                        "return_type": "PREFIXTARGETTYPESUFFIX",
                        "parameter_types": "[]",
                    }
                )

            rows = query_method_references(path, "targettype")
            self.assertEqual(2, len(rows))
            self.assertTrue(rows[0]["self_type"])
            self.assertEqual([0], rows[0]["parameter_positions"])
            self.assertTrue(rows[1]["match_parameter"])
            self.assertTrue(rows[1]["match_return"])

            external = query_method_references(path, "TARGETTYPE", external_only=True)
            self.assertEqual(1, len(external))
            self.assertEqual("OWNER", external[0]["type_name"])
            self.assertFalse(external[0]["self_type"])

    def test_query_method_references_escapes_regex_metacharacters(self) -> None:
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
                        "return_type",
                        "parameter_types",
                    ],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "method_index": "1",
                        "type_definition_index": "10",
                        "type_name": "OWNER",
                        "method_name": "Exact",
                        "rva": "0x1000",
                        "return_type": "Wrapper<A+B>",
                        "parameter_types": "[]",
                    }
                )
                writer.writerow(
                    {
                        "method_index": "2",
                        "type_definition_index": "20",
                        "type_name": "OWNER",
                        "method_name": "RegexLike",
                        "rva": "0x2000",
                        "return_type": "Wrapper<AAAB>",
                        "parameter_types": "[]",
                    }
                )

            rows = query_method_references(path, "A+B")
            self.assertEqual(1, len(rows))
            self.assertEqual("Exact", rows[0]["method_name"])
            self.assertTrue(rows[0]["match_return"])

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
