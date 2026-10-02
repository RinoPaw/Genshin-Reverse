from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from genshinre.versionvalidate import validate_version


class MaintainedVersionValidatorTests(unittest.TestCase):
    def test_composes_manifest_v2_contract(self) -> None:
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
            with patch("genshinre.versionvalidate.validate_core_version", return_value=([], [])):
                errors, warnings = validate_version(root, allow_partial=True)
            self.assertEqual(warnings, [])
            self.assertTrue(any("manifest_version must be 2" in error for error in errors))

    def test_composes_cmd_observation_contract(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            observations = root / "cmdids" / "observations.csv"
            observations.parent.mkdir(parents=True)
            observations.write_text(
                "name,cmd_id,direction,status,evidence\n"
                "UNKNOWN_186,186,SERVERBOUND,UNRESOLVED,fixture\n",
                encoding="utf-8",
            )
            with patch("genshinre.versionvalidate.validate_core_version", return_value=([], [])):
                errors, _ = validate_version(root, allow_partial=True)
            self.assertTrue(any("bad direction SERVERBOUND" in error for error in errors))

    def test_composes_xref_contract(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            table = root / "xrefs" / "message-senders.csv"
            table.parent.mkdir(parents=True)
            table.write_text(
                "cmd_id,type_name,sender_type,sender_method,sender_rva,context,status,evidence\n"
                "186,NLOMEGMJDGJ,,,BAD,fixture,CANDIDATE,fixture\n",
                encoding="utf-8",
            )
            with patch("genshinre.versionvalidate.validate_core_version", return_value=([], [])):
                errors, _ = validate_version(root, allow_partial=True)
            self.assertTrue(any("bad sender_rva BAD" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
