from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from genshinre.metadataquery import (
    query_method_evidence,
    query_method_references,
    query_methods,
)


class MetadataEvidenceQueryTests(unittest.TestCase):
    def test_combined_query_matches_separate_method_queries(self) -> None:
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
                writer.writerows(
                    [
                        {
                            "method_index": "1",
                            "type_definition_index": "10",
                            "type_name": "TARGET",
                            "method_name": "Own",
                            "rva": "0x1000",
                            "return_type": "void",
                            "parameter_types": "[]",
                        },
                        {
                            "method_index": "2",
                            "type_definition_index": "20",
                            "type_name": "OWNER",
                            "method_name": "Handle",
                            "rva": "0x2000",
                            "return_type": "TARGET",
                            "parameter_types": '["TARGET"]',
                        },
                        {
                            "method_index": "3",
                            "type_definition_index": "30",
                            "type_name": "OTHER",
                            "method_name": "Ignore",
                            "rva": "0x3000",
                            "return_type": "void",
                            "parameter_types": "[]",
                        },
                    ]
                )

            methods, references = query_method_evidence(
                path,
                type_definition_index=10,
                referenced_type="TARGET",
            )

            self.assertEqual(
                query_methods(path, type_definition_index=10),
                methods,
            )
            self.assertEqual(
                query_method_references(path, "TARGET"),
                references,
            )


if __name__ == "__main__":
    unittest.main()
