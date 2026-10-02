from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from genshinre.registry import CANONICAL_REGISTRY_COLUMNS
from genshinre.validate import _validate_generated_artifacts


class GeneratedArtifactManifestTests(unittest.TestCase):
    def _write_manifest(self, root: Path, data: dict) -> None:
        (root / "generated-artifacts.json").write_text(
            json.dumps(data), encoding="utf-8"
        )

    def _write_canonical_registry(self, root: Path) -> None:
        registry = root / "registry"
        registry.mkdir(exist_ok=True)
        row = {column: "" for column in CANONICAL_REGISTRY_COLUMNS}
        row.update(
            {
                "index": "0",
                "cmd_id": "1",
                "type_name": "TYPE_1",
                "type_definition_index": "1",
                "direction": "C2S",
                "direction_status": "control-confirmed",
                "type_slot_rva": "0x1000",
                "status": "static-verified-identity",
                "evidence": "unit test",
            }
        )
        with (registry / "registry.csv").open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CANONICAL_REGISTRY_COLUMNS)
            writer.writeheader()
            writer.writerow(row)
        (registry / "registry.summary.json").write_text(
            json.dumps(
                {
                    "status": "canonical-static-identity-registry",
                    "row_count": 1,
                    "unique_cmd_ids": 1,
                    "strict_slot_type_cmd_bijection": True,
                }
            ),
            encoding="utf-8",
        )

    def test_valid_manifest_accepts_existing_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_canonical_registry(root)
            (root / "registry" / "control-set.csv").write_text("cmd_id\n1\n", encoding="utf-8")
            (root / "metadata").mkdir()
            (root / "metadata" / "types.csv").write_text("type_name\n", encoding="utf-8")
            self._write_manifest(
                root,
                {
                    "canonical_registry_published": True,
                    "optional_registry_artifacts_published": ["registry/control-set.csv"],
                    "artifacts": [
                        "generated-artifacts.json",
                        "registry/registry.csv",
                        "registry/registry.summary.json",
                        "registry/control-set.csv",
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

    def test_missing_optional_artifact_uses_version_root_relative_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_manifest(
                root,
                {
                    "canonical_registry_published": False,
                    "optional_registry_artifacts_published": ["registry/missing.csv"],
                    "artifacts": [],
                },
            )

            errors: list[str] = []
            _validate_generated_artifacts(root, errors, [])

            self.assertTrue(
                any("listed artifact does not exist: registry/missing.csv" in error for error in errors)
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
            self.assertTrue(any("must stay inside the publication directory" in error for error in errors))

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

    def test_registry_publication_flag_requires_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "registry").mkdir()
            (root / "registry" / "registry.csv").write_text("cmd_id\n1\n", encoding="utf-8")
            self._write_manifest(
                root,
                {
                    "canonical_registry_published": True,
                    "optional_registry_artifacts_published": [],
                    "artifacts": ["generated-artifacts.json", "registry/registry.csv"],
                },
            )

            errors: list[str] = []
            _validate_generated_artifacts(root, errors, [])

            self.assertTrue(any("registry/registry.summary.json is missing" in error for error in errors))

    def test_registry_publication_requires_exact_canonical_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_canonical_registry(root)
            (root / "registry" / "registry.csv").write_text("cmd_id\n1\n", encoding="utf-8")
            self._write_manifest(
                root,
                {
                    "canonical_registry_published": True,
                    "optional_registry_artifacts_published": [],
                    "artifacts": [
                        "generated-artifacts.json",
                        "registry/registry.csv",
                        "registry/registry.summary.json",
                    ],
                },
            )

            errors: list[str] = []
            _validate_generated_artifacts(root, errors, [])

            self.assertTrue(any("canonical header mismatch" in error for error in errors))

    def test_registry_summary_must_match_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_canonical_registry(root)
            summary_path = root / "registry" / "registry.summary.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            summary["row_count"] = 2
            summary_path.write_text(json.dumps(summary), encoding="utf-8")
            self._write_manifest(
                root,
                {
                    "canonical_registry_published": True,
                    "optional_registry_artifacts_published": [],
                    "artifacts": [
                        "generated-artifacts.json",
                        "registry/registry.csv",
                        "registry/registry.summary.json",
                    ],
                },
            )

            errors: list[str] = []
            _validate_generated_artifacts(root, errors, [])

            self.assertTrue(any("row_count does not match registry.csv" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
