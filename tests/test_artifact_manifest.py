from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from genshinre.artifactmanifest import (
    REQUIRED_PUBLICATION_ROWS,
    validate_generated_manifest,
)


class GeneratedArtifactManifestV3Tests(unittest.TestCase):
    def test_committed_manifest_matches_v3_contract(self) -> None:
        root = Path(__file__).resolve().parents[1] / "versions/7.1.0-global/windows-x64"
        self.assertEqual([], validate_generated_manifest(root))

    def test_rejects_retired_fields(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "ok.csv").write_text("x\n", encoding="utf-8")
            (root / "generated-artifacts.json").write_text(
                json.dumps(
                    {
                        "manifest_version": 3,
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

    def test_rejects_manifest_v2(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "generated-artifacts.json").write_text(
                json.dumps(
                    {
                        "manifest_version": 2,
                        "canonical_registry_published": True,
                        "artifacts": [],
                    }
                ),
                encoding="utf-8",
            )
            errors = validate_generated_manifest(root)
            self.assertTrue(any("manifest_version must be 3" in error for error in errors))

    def test_requires_canonical_registry_publication(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "generated-artifacts.json").write_text(
                json.dumps(
                    {
                        "manifest_version": 3,
                        "canonical_registry_published": False,
                        "artifacts": [],
                    }
                ),
                encoding="utf-8",
            )
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
                        "manifest_version": 3,
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
            for rel in REQUIRED_PUBLICATION_ROWS:
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture\n", encoding="utf-8")

            metadata_rows = {rel: 1 for rel in REQUIRED_PUBLICATION_ROWS}
            (root / "generated-artifacts.json").write_text(
                json.dumps(
                    {
                        "manifest_version": 3,
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
                                "exe_sha256": "0" * 64,
                                "metadata_sha256": metadata_sha,
                            },
                            "runtime_type_anchor": True,
                            "getcmdid_anchor": True,
                        },
                        "publication": {
                            "metadata_format": "compact-query-indexes",
                            "metadata_rows": metadata_rows,
                        },
                        "artifacts": list(REQUIRED_PUBLICATION_ROWS),
                    }
                ),
                encoding="utf-8",
            )

            errors = validate_generated_manifest(root)
            self.assertTrue(
                any("exe_sha256 does not match hashes.json" in error for error in errors)
            )


if __name__ == "__main__":
    unittest.main()
