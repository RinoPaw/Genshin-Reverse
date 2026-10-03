from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
DOC = ROOT / "docs" / "workflows.md"


class WorkflowDocumentationTests(unittest.TestCase):
    def test_all_documented_workflow_files_exist(self) -> None:
        text = DOC.read_text(encoding="utf-8")
        names = sorted(set(re.findall(r"`([A-Za-z0-9._-]+\.yml)`", text)))

        self.assertTrue(names, "docs/workflows.md should name maintained workflow files")
        missing = [name for name in names if not (WORKFLOWS / name).is_file()]
        self.assertEqual([], missing)


if __name__ == "__main__":
    unittest.main()
