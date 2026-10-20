"""Synthetic, source-independent regression tests for historical ancestry audit."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/audit-chest-drop-ancestry.py"

spec = importlib.util.spec_from_file_location("chest_drop_ancestry", SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def row(tag="战斗低级蒙德", root=51010000):
    return (1, tag, root, 1, 19, "战斗")


class ChestDropAncestryTest(unittest.TestCase):
    def test_exact_subset_and_extra_rows(self):
        old = [row(), row()]
        new = old + [row("解谜低级蒙德", 52010000)]
        result = audit.compare(old, new)
        self.assertEqual((2, 0, 1), (
            result["unchangedHistoricalRows"],
            result["historicalMissingOrChangedRows"],
            result["serverAdditionalRows"],
        ))
        self.assertTrue(result["historicalIsExactMultisetSubset"])
        self.assertFalse(result["native71Verified"])

    def test_modified_row_and_multiplicity_are_not_contained(self):
        result = audit.compare([row(), row()], [row(), row(root=51010100)])
        self.assertFalse(result["historicalIsExactMultisetSubset"])
        self.assertEqual(1, result["historicalMissingOrChangedRows"])
        self.assertEqual(1, result["serverAdditionalRows"])

    def test_raw_tsv_and_git_blob_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / "ChestDropData.txt"
            old.write_text("\t".join(audit.HEADERS) + "\n1\t战斗低级蒙德\t51010000\t1\t19\t战斗\n", encoding="utf-8")
            self.assertEqual([row()], audit.historical(old))
            result = subprocess.run([sys.executable, str(SCRIPT), "--historical", str(old),
                  "--server", str(old), "--historical-blob", "0" * 40], capture_output=True, text=True)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("Git blob changed", result.stderr)
            old.write_text("wrong headers\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                audit.historical(old)


if __name__ == "__main__":
    unittest.main()
