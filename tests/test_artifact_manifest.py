from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from genshinre.artifactmanifest import validate_generated_manifest


class GeneratedArtifactManifestV2Tests(unittest.TestCase):
    def test_committed_manifest_matches_v2_contract(self) -> None:
        root = Path(__file__).resolve().parents[1] / "versions/7.1.0-global/windows-x64"
        self.assertEqual([], validate_generated_manifest(root))

    def test_rejects_legacy_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "ok.csv").write_text("x\n", encoding="utf-8")
            (root / "generated-artifacts.json").write_text(
                json.dumps(
                    {
                        "manifest_version": 2,
                        "canonical_registry_published": False,
                        "files": ["ok.csv"],
                        "artifacts": ["ok.csv"],
                        "optional_registry_artifacts_published": [],
                        "optional_artifacts_published": [],
                    }
                ),
                encoding="utf-8",
            )
            errors = validate_generated_manifest(root)
            self.assertTrue(any("legacy field 'files'" in error for error in errors))
            self.assertTrue(
                any("optional_registry_artifacts_published" in error for error in errors)
            )

    def test_optional_entries_must_be_published_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "required.csv").write_text("x\n", encoding="utf-8")
            (root / "optional.csv").write_text("x\n", encoding="utf-8")
            (root / "generated-artifacts.json").write_text(
                json.dumps(
                    {
                        "manifest_version": 2,
                        "canonical_registry_published": False,
                        "artifacts": ["required.csv"],
                        "optional_artifacts_published": ["optional.csv"],
                    }
                ),
                encoding="utf-8",
            )
            errors = validate_generated_manifest(root)
            self.assertTrue(any("must be a subset of artifacts" in error for error in errors))

    def test_rejects_missing_and_parent_paths(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "generated-artifacts.json").write_text(
                json.dumps(
                    {
                        "manifest_version": 2,
                        "canonical_registry_published": False,
                        "artifacts": ["missing.csv", "../escape.csv"],
                        "optional_artifacts_published": [],
                    }
                ),
                encoding="utf-8",
            )
            errors = validate_generated_manifest(root)
            self.assertTrue(any("listed artifact does not exist: missing.csv" in error for error in errors))
            self.assertTrue(any("must stay inside the publication directory" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
