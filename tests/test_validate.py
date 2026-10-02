from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from genshinre.validate import _validate_generated_artifacts


class GeneratedArtifactManifestTests(unittest.TestCase):
    def _write_manifest(self, root: Path, data: dict) -> None:
        (root / "generated-artifacts.json").write_text(
            json.dumps(data), encoding="utf-8"
        )

    def test_valid_manifest_accepts_existing_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "registry").mkdir()
            (root / "registry" / "registry.csv").write_text("cmd_id\n", encoding="utf-8")
            (root / "metadata").mkdir()
            (root / "metadata" / "types.csv").write_text("type_name\n", encoding="utf-8")
            self._write_manifest(
                root,
                {
                    "canonical_registry_published": True,
                    "optional_registry_artifacts_published": [],
                    "artifacts": [
                        "generated-artifacts.json",
                        "registry/registry.csv",
                        "metadata/types.csv",
                    ],
                },
            )

            errors: list[str] = []
            warnings: list[str] = []
            _validate_generated_artifacts(root, errors, warnings)

            self.assertEqual(errors, [])
            self.assertEqual(warnings, [])

    def test_missing_listed_artifact_is_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_manifest(
                root,
                {
                    "canonical_registry_published": False,
                    "optional_registry_artifacts_published": [],
                    "artifacts": ["missing.csv"],
                },
            )

            errors: list[str] = []
            _validate_generated_artifacts(root, errors, [])

            self.assertTrue(
                any("listed artifact does not exist: missing.csv" in error for error in errors)
            )

    def test_duplicate_and_parent_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ok.csv").write_text("x\n", encoding="utf-8")
            self._write_manifest(
                root,
                {
                    "canonical_registry_published": False,
                    "optional_registry_artifacts_published": [],
                    "artifacts": ["ok.csv", "ok.csv", "../escape.csv"],
                },
            )

            errors: list[str] = []
            _validate_generated_artifacts(root, errors, [])

            self.assertTrue(any("duplicate path ok.csv" in error for error in errors))
            self.assertTrue(any("must stay inside the version directory" in error for error in errors))

    def test_registry_publication_flag_requires_registry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_manifest(
                root,
                {
                    "canonical_registry_published": True,
                    "optional_registry_artifacts_published": [],
                    "artifacts": ["generated-artifacts.json"],
                },
            )

            errors: list[str] = []
            _validate_generated_artifacts(root, errors, [])

            self.assertTrue(
                any("canonical_registry_published is true" in error for error in errors)
            )


if __name__ == "__main__":
    unittest.main()
