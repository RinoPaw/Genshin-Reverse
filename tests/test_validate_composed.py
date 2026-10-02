from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from genshinre.validate import validate_version


class ComposedValidatorTests(unittest.TestCase):
    def test_manifest_v2_contract_runs_through_canonical_validator(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "generated-artifacts.json").write_text(
                json.dumps(
                    {
                        "manifest_version": 1,
                        "canonical_registry_published": False,
                        "artifacts": [],
                        "optional_artifacts_published": [],
                    }
                ),
                encoding="utf-8",
            )
            errors, _ = validate_version(root, allow_partial=True)
            self.assertTrue(any("manifest_version must be 2" in error for error in errors))

    def test_cmd_observation_contract_runs_through_canonical_validator(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            observations = root / "cmdids" / "observations.csv"
            observations.parent.mkdir(parents=True)
            observations.write_text(
                "name,cmd_id,direction,status,evidence\n"
                "UNKNOWN_186,186,SERVERBOUND,UNRESOLVED,fixture\n",
                encoding="utf-8",
            )
            errors, _ = validate_version(root, allow_partial=True)
            self.assertTrue(any("bad direction SERVERBOUND" in error for error in errors))

    def test_xref_contract_runs_through_canonical_validator(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            table = root / "xrefs" / "message-senders.csv"
            table.parent.mkdir(parents=True)
            table.write_text(
                "cmd_id,type_name,sender_type,sender_method,sender_rva,context,status,evidence\n"
                "186,NLOMEGMJDGJ,,,BAD,fixture,CANDIDATE,fixture\n",
                encoding="utf-8",
            )
            errors, _ = validate_version(root, allow_partial=True)
            self.assertTrue(any("bad sender_rva BAD" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
