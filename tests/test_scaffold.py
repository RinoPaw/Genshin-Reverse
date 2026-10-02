from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from genshinre.registry import CANONICAL_REGISTRY_COLUMNS
from genshinre.scaffold import DIRECTORIES, scaffold


class ScaffoldTests(unittest.TestCase):
    def test_current_layout_includes_cmdids_evidence_directory(self) -> None:
        self.assertIn("cmdids", DIRECTORIES)

    def test_scaffold_uses_current_registry_contract_without_empty_evidence_files(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = scaffold(root, "7.2.0", "global", "windows-x64")

            for directory in DIRECTORIES:
                self.assertTrue((target / directory).is_dir(), directory)

            with (target / "registry/registry.csv").open(
                "r", encoding="utf-8", newline=""
            ) as f:
                self.assertEqual(tuple(next(csv.reader(f))), CANONICAL_REGISTRY_COLUMNS)

            self.assertTrue((target / "proto/known-opcodes.csv").is_file())
            self.assertTrue((target / "proto/message-shapes.json").is_file())
            self.assertFalse((target / "cmdids/observations.csv").exists())
            self.assertFalse((target / "generated-artifacts.json").exists())


if __name__ == "__main__":
    unittest.main()
