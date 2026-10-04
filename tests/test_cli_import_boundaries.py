from __future__ import annotations

import ast
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "genshinre" / "cli.py"


class CliImportBoundaryTests(unittest.TestCase):
    def test_cli_has_no_top_level_package_imports(self) -> None:
        tree = ast.parse(CLI.read_text(encoding="utf-8"), filename=str(CLI))
        violations = [
            node.lineno
            for node in tree.body
            if isinstance(node, ast.ImportFrom) and node.level > 0
        ]
        self.assertEqual([], violations)

    def test_building_parser_does_not_load_command_implementations(self) -> None:
        code = """
import sys
from genshinre.cli import build_parser
build_parser()
forbidden = {
    'genshinre.mhy71',
    'genshinre.getcmdid',
    'genshinre.callxref',
    'genshinre.capture',
    'genshinre.protocolquery',
    'genshinre.validate',
}
loaded = sorted(forbidden.intersection(sys.modules))
if loaded:
    raise SystemExit('eager command imports: ' + ', '.join(loaded))
"""
        subprocess.run([sys.executable, "-c", code], cwd=ROOT, check=True)


if __name__ == "__main__":
    unittest.main()
