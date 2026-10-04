from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
README = TOOLS / "README.md"


class ToolsContractTests(unittest.TestCase):
    def test_every_top_level_python_helper_is_documented(self) -> None:
        text = README.read_text(encoding="utf-8")
        helpers = sorted(path.name for path in TOOLS.glob("*.py"))

        self.assertTrue(helpers)
        for name in helpers:
            with self.subTest(tool=name):
                self.assertIn(f"`{name}`", text)

    def test_runtime_helper_directory_is_documented(self) -> None:
        text = README.read_text(encoding="utf-8")

        self.assertTrue((TOOLS / "runtime").is_dir())
        self.assertIn("`runtime/`", text)


if __name__ == "__main__":
    unittest.main()
