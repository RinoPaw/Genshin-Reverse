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

    def test_push_triggered_exact_sample_workflows_cancel_stale_runs(self) -> None:
        offenders: list[str] = []
        for path in sorted(WORKFLOWS.glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            uses_exact_sample = "scripts/fetch-7.1-samples.sh" in text
            push_triggered = re.search(r"(?m)^\s{2}push:\s*$", text) is not None
            if uses_exact_sample and push_triggered and "cancel-in-progress: true" not in text:
                offenders.append(path.name)

        self.assertEqual([], offenders)


if __name__ == "__main__":
    unittest.main()
