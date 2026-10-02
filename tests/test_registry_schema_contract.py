from __future__ import annotations

import json
import unittest
from pathlib import Path

from genshinre.registry import CANONICAL_REGISTRY_COLUMNS
from genshinre.registryxrefpublish import (
    COLUMNS as XREF_PUBLISH_COLUMNS,
    SUMMARY_IDENTITY_METHOD,
    SUMMARY_PRODUCER,
    SUMMARY_SEMANTIC_ENRICHMENT,
)


class RegistrySchemaContractTests(unittest.TestCase):
    def test_xref_publisher_matches_canonical_registry_schema(self) -> None:
        self.assertEqual(CANONICAL_REGISTRY_COLUMNS, XREF_PUBLISH_COLUMNS)

    def test_json_schema_matches_canonical_registry_columns(self) -> None:
        schema_path = Path(__file__).resolve().parents[1] / "schemas" / "registry.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))

        self.assertEqual(CANONICAL_REGISTRY_COLUMNS, tuple(schema["required"]))
        self.assertEqual(set(CANONICAL_REGISTRY_COLUMNS), set(schema["properties"]))
        self.assertFalse(schema["additionalProperties"])

    def test_committed_registry_summary_matches_publisher_provenance(self) -> None:
        summary_path = (
            Path(__file__).resolve().parents[1]
            / "versions"
            / "7.1.0-global"
            / "windows-x64"
            / "registry"
            / "registry.summary.json"
        )
        summary = json.loads(summary_path.read_text(encoding="utf-8"))

        self.assertEqual(SUMMARY_PRODUCER, summary["producer"])
        self.assertEqual(SUMMARY_IDENTITY_METHOD, summary["identity_method"])
        self.assertEqual(SUMMARY_SEMANTIC_ENRICHMENT, summary["semantic_enrichment"])


if __name__ == "__main__":
    unittest.main()
