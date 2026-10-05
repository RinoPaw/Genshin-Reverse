from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
WORKFLOW_DOC = ROOT / "docs" / "workflows.md"


class WorkflowPolicyTests(unittest.TestCase):
    def workflow_files(self) -> list[Path]:
        return sorted(WORKFLOWS.glob("*.yml"))

    def workflow_text(self, path: Path) -> str:
        return path.read_text(encoding="utf-8")

    def test_every_workflow_is_documented(self) -> None:
        documented = WORKFLOW_DOC.read_text(encoding="utf-8")
        for path in self.workflow_files():
            with self.subTest(workflow=path.name):
                self.assertIn(f"`{path.name}`", documented)

    def test_every_workflow_declares_permissions(self) -> None:
        for path in self.workflow_files():
            with self.subTest(workflow=path.name):
                self.assertRegex(
                    self.workflow_text(path),
                    r"(?m)^permissions:\s*$",
                    "workflow must declare explicit top-level permissions",
                )

    def test_push_workflows_cancel_stale_runs(self) -> None:
        for path in self.workflow_files():
            text = self.workflow_text(path)
            if not re.search(r"(?m)^  push:\s*$", text):
                continue
            with self.subTest(workflow=path.name):
                self.assertRegex(
                    text,
                    r"(?m)^concurrency:\s*$",
                    "push workflow must define a concurrency group",
                )
                self.assertRegex(
                    text,
                    r"(?m)^  cancel-in-progress:\s*true\s*$",
                    "push workflow must cancel stale runs",
                )

    def test_repository_write_workflow_is_allowlisted(self) -> None:
        writers = []
        for path in self.workflow_files():
            if re.search(r"(?m)^  contents:\s*write\s*$", self.workflow_text(path)):
                writers.append(path.name)
        self.assertEqual(["generate-7.1-data.yml"], writers)


if __name__ == "__main__":
    unittest.main()
