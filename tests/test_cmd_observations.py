from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from genshinre.cmdobservations import validate_observation_summary


class CmdObservationTests(unittest.TestCase):
    def test_committed_summary_matches_contract(self) -> None:
        root = Path(__file__).resolve().parents[1]
        path = root / "versions/7.1.0-global/windows-x64/cmdids/observations.csv"
        self.assertEqual([], validate_observation_summary(path))

    def test_allows_blank_cmdid_for_named_unresolved_target(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "observations.csv"
            path.write_text(
                "name,cmd_id,direction,status,evidence\n"
                "SomeRsp,,S2C,UNRESOLVED,current mapping unknown\n",
                encoding="utf-8",
            )
            self.assertEqual([], validate_observation_summary(path))

    def test_rejects_bad_direction_and_missing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "observations.csv"
            path.write_text(
                "name,cmd_id,direction,status,evidence\n"
                "UNKNOWN_186,186,SERVERBOUND,UNRESOLVED,\n",
                encoding="utf-8",
            )
            errors = validate_observation_summary(path)
            self.assertTrue(any("bad direction" in error for error in errors))
            self.assertTrue(any("evidence must be non-empty" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
