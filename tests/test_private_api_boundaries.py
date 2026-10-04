from __future__ import annotations

import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PrivateApiBoundaryTests(unittest.TestCase):
    def test_production_modules_do_not_import_private_names_from_other_modules(self) -> None:
        paths = [
            *sorted((ROOT / "genshinre").glob("*.py")),
            *sorted((ROOT / "tools").rglob("*.py")),
        ]
        violations: list[str] = []
        for path in paths:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.ImportFrom):
                    continue
                for alias in node.names:
                    if alias.name.startswith("_"):
                        violations.append(
                            f"{path.relative_to(ROOT)}:{node.lineno}: imports private name {alias.name}"
                        )
        self.assertEqual([], violations)


if __name__ == "__main__":
    unittest.main()
