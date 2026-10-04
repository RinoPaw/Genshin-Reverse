from __future__ import annotations

import ast
import unittest
from pathlib import Path

import genshinre.metadata as metadata
import genshinre.metadatacsv as metadatacsv
import genshinre.metadataindex as metadataindex
import genshinre.registry as registry
import genshinre.registrycontract as registrycontract


ROOT = Path(__file__).resolve().parents[1]


class GenerationDependencyBoundaryTests(unittest.TestCase):
    def test_public_compatibility_surfaces_reexport_generation_contracts(self) -> None:
        self.assertIs(metadataindex.build_type_methods, metadata.build_type_methods)
        self.assertEqual(
            registrycontract.CANONICAL_REGISTRY_COLUMNS,
            registry.CANONICAL_REGISTRY_COLUMNS,
        )
        self.assertEqual(registrycontract.ALLOWED_STATUS, registry.ALLOWED_STATUS)
        self.assertEqual(
            registrycontract.EXPECTED_REGISTRY_ROW_COUNT,
            registry.EXPECTED_REGISTRY_ROW_COUNT,
        )

    def test_parameter_type_parser_is_shared_generation_contract(self) -> None:
        self.assertEqual([], metadatacsv.parse_parameter_types(""))
        self.assertEqual(["Alpha", "2"], metadatacsv.parse_parameter_types('["Alpha", 2]'))
        with self.assertRaisesRegex(ValueError, "JSON array"):
            metadatacsv.parse_parameter_types('{"type":"Alpha"}')

    def test_heavy_workflow_tracks_facades_and_generation_contracts(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "generate-7.1-data.yml").read_text(
            encoding="utf-8"
        )
        for path in (
            "genshinre/metadata.py",
            "genshinre/metadatacsv.py",
            "genshinre/metadataindex.py",
            "genshinre/registry.py",
            "genshinre/registrycontract.py",
        ):
            with self.subTest(path=path):
                self.assertIn(f"- '{path}'", workflow)
        for path in ("genshinre/metadataquery.py", "genshinre/registryquery.py"):
            with self.subTest(path=path):
                self.assertNotIn(f"- '{path}'", workflow)

    def test_generation_facades_do_not_eagerly_import_query_modules(self) -> None:
        for relative, forbidden in (
            ("genshinre/metadata.py", "metadataquery"),
            ("genshinre/registry.py", "registryquery"),
        ):
            tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
            top_level_imports = [
                node
                for node in tree.body
                if isinstance(node, (ast.Import, ast.ImportFrom))
            ]
            rendered = ast.dump(ast.Module(body=top_level_imports, type_ignores=[]))
            with self.subTest(path=relative):
                self.assertNotIn(forbidden, rendered)


if __name__ == "__main__":
    unittest.main()
