from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from genshinre.analysis import research_status


class AnalysisStatusTests(unittest.TestCase):
    def test_research_status_summarizes_machine_readable_analyses(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            active = root / "analyses" / "active-case"
            active.mkdir(parents=True)
            (root / "analyses" / "legacy-case").mkdir()
            (active / "evidence.json").write_text(
                json.dumps(
                    {
                        "topic": "active-case",
                        "state": "ACTIVE",
                        "claims": [
                            {"id": "confirmed", "status": "CONFIRMED", "statement": "done"},
                            {"id": "candidate", "status": "CANDIDATE", "statement": "open"},
                            {"id": "rejected", "status": "REJECTED", "statement": "closed"},
                        ],
                        "next_steps": ["resolve candidate"],
                    }
                ),
                encoding="utf-8",
            )

            result = research_status(root)
            self.assertEqual(1, result["topic_count"])
            self.assertEqual({"ACTIVE": 1}, result["state_counts"])
            self.assertEqual(1, result["claim_status_counts"]["CONFIRMED"])
            self.assertEqual(1, result["claim_status_counts"]["CANDIDATE"])
            self.assertEqual(["legacy-case"], result["legacy_without_evidence"])
            self.assertEqual(["candidate"], [claim["id"] for claim in result["topics"][0]["open_claims"]])


if __name__ == "__main__":
    unittest.main()
