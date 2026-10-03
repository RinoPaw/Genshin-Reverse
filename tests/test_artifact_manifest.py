from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from genshinre.artifactmanifest import (
    CANONICAL_ARTIFACTS,
    REQUIRED_PUBLICATION_ROWS,
    validate_generated_manifest,
)
from genshinre.nativeprofile import PROFILE_71

EXPECTED_RUNTIME_TYPE_COUNT = PROFILE_71.runtime_type_count


class GeneratedArtifactManifestV4Tests(unittest.TestCase):
    def _write_valid_fixture(self, root: Path) -> dict[str, object]:
        exe_sha = "e" * 64
        metadata_sha = "d" * 64
        (root / "hashes.json").write_text(
            json.dumps(
                {
                    "game_version": "7.1.0",
                    "region": "global",
                    "platform": "windows-x64",
                    "samples": {
                        "GenshinImpact.exe": {"sha256": exe_sha},
                        "global-metadata.dat": {"sha256": metadata_sha},
                    },
                }
            ),
            encoding="utf-8",
        )
        for rel in CANONICAL_ARTIFACTS:
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture\n", encoding="utf-8")

        runtime_summary = {
            "exe_sha256": exe_sha,
            "status": "canonical-exact-runtime-type-index",
            "runtime_type_count": EXPECTED_RUNTIME_TYPE_COUNT,
            "type_array_rva": "0x1000",
            "boundary_rva": "0xA6F360",
            "boundary_entry_hex": "8988883b0000000060da9e4501000000",
            "boundary_entry_valid_type": False,
            "structural_validation_passed": True,
            "emitted_rows": 1,
            "named_definition_entries": 1,
            "anchor_405772_class_84249_DMMJNICDOHM": True,
        }
        (root / "metadata/runtime-types.summary.json").write_text(
            json.dumps(runtime_summary), encoding="utf-8"
        )

        data: dict[str, object] = {
            "manifest_version": 4,
            "source": "genshinre.artifactpublish",
            "status": "generated-artifacts-published",
            "canonical_registry_published": True,
            "validation": {
                "metadata_counts": {
                    "types": 1,
                    "fields": 1,
                    "methods": 1,
                    "method_pointers": 1,
                },
                "sample": {
                    "exe_sha256": exe_sha,
                    "metadata_sha256": metadata_sha,
                },
                "runtime_type_anchor": True,
                "runtime_type_count": EXPECTED_RUNTIME_TYPE_COUNT,
                "runtime_type_boundary_rva": "0xA6F360",
                "runtime_type_boundary_verified": True,
                "getcmdid_anchor": True,
            },
            "publication": {
                "metadata_format": "compact-query-indexes",
                "metadata_rows": {rel: 1 for rel in REQUIRED_PUBLICATION_ROWS},
            },
            "artifacts": list(CANONICAL_ARTIFACTS),
        }
        (root / "generated-artifacts.json").write_text(
            json.dumps(data), encoding="utf-8"
        )
        return data

    def test_committed_manifest_matches_v4_contract(self) -> None:
        root = Path(__file__).resolve().parents[1] / "versions/7.1.0-global/windows-x64"
        self.assertEqual([], validate_generated_manifest(root))

    def test_valid_fixture_matches_v4_contract(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write_valid_fixture(root)
            self.assertEqual([], validate_generated_manifest(root))

    def test_rejects_retired_fields(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "ok.csv").write_text("x\n", encoding="utf-8")
            (root / "generated-artifacts.json").write_text(
                json.dumps(
                    {
                        "manifest_version": 4,
                        "canonical_registry_published": True,
                        "files": ["ok.csv"],
                        "artifacts": ["ok.csv"],
                        "optional_registry_artifacts_published": [],
                        "optional_artifacts_published": [],
                    }
                ),
                encoding="utf-8",
            )
            errors = validate_generated_manifest(root)
            for field in (
                "files",
                "optional_registry_artifacts_published",
                "optional_artifacts_published",
            ):
                self.assertTrue(any(field in error for error in errors), field)

    def test_rejects_manifest_v3(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "generated-artifacts.json").write_text(
                json.dumps(
                    {
                        "manifest_version": 3,
                        "canonical_registry_published": True,
                        "artifacts": [],
                    }
                ),
                encoding="utf-8",
            )
            errors = validate_generated_manifest(root)
            self.assertTrue(any("manifest_version must be 4" in error for error in errors))

    def test_requires_canonical_registry_publication(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data = self._write_valid_fixture(root)
            data["canonical_registry_published"] = False
            (root / "generated-artifacts.json").write_text(json.dumps(data), encoding="utf-8")
            errors = validate_generated_manifest(root)
            self.assertTrue(
                any("canonical_registry_published must be true" in error for error in errors)
            )

    def test_rejects_missing_and_parent_paths(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "generated-artifacts.json").write_text(
                json.dumps(
                    {
                        "manifest_version": 4,
                        "canonical_registry_published": True,
                        "artifacts": ["missing.csv", "../escape.csv"],
                    }
                ),
                encoding="utf-8",
            )
            errors = validate_generated_manifest(root)
            self.assertTrue(any("listed artifact does not exist: missing.csv" in error for error in errors))
            self.assertTrue(any("must stay inside the publication directory" in error for error in errors))

    def test_rejects_sample_hash_drift(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data = self._write_valid_fixture(root)
            validation = data["validation"]
            assert isinstance(validation, dict)
            sample = validation["sample"]
            assert isinstance(sample, dict)
            sample["exe_sha256"] = "0" * 64
            (root / "generated-artifacts.json").write_text(json.dumps(data), encoding="utf-8")

            errors = validate_generated_manifest(root)
            self.assertTrue(
                any("exe_sha256 does not match hashes.json" in error for error in errors)
            )

    def test_rejects_runtime_count_drift(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data = self._write_valid_fixture(root)
            validation = data["validation"]
            assert isinstance(validation, dict)
            validation["runtime_type_count"] = EXPECTED_RUNTIME_TYPE_COUNT - 1
            (root / "generated-artifacts.json").write_text(json.dumps(data), encoding="utf-8")

            errors = validate_generated_manifest(root)
            self.assertTrue(any("runtime_type_count must be 683574" in error for error in errors))

    def test_rejects_runtime_summary_boundary_drift(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write_valid_fixture(root)
            summary_path = root / "metadata/runtime-types.summary.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            summary["boundary_rva"] = "0xA6F370"
            summary_path.write_text(json.dumps(summary), encoding="utf-8")

            errors = validate_generated_manifest(root)
            self.assertTrue(any("type_array_rva + runtime_type_count * 16" in error for error in errors))

    def test_rejects_runtime_structural_gate_loss(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write_valid_fixture(root)
            summary_path = root / "metadata/runtime-types.summary.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            summary["structural_validation_passed"] = False
            summary_path.write_text(json.dumps(summary), encoding="utf-8")

            errors = validate_generated_manifest(root)
            self.assertTrue(any("structural_validation_passed must be true" in error for error in errors))

    def test_rejects_extra_publication_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data = self._write_valid_fixture(root)
            extra = root / "registry" / "control-set.csv"
            extra.write_text("cmd_id\n1\n", encoding="utf-8")
            artifacts = data["artifacts"]
            assert isinstance(artifacts, list)
            artifacts.append("registry/control-set.csv")
            (root / "generated-artifacts.json").write_text(json.dumps(data), encoding="utf-8")

            errors = validate_generated_manifest(root)
            self.assertTrue(
                any("artifacts must equal the canonical publication set" in error for error in errors)
            )


if __name__ == "__main__":
    unittest.main()
