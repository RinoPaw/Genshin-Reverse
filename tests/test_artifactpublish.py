from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from genshinre.artifactpublish import publish_generated_artifacts_71


class ArtifactPublishTests(unittest.TestCase):
    def _write_csv(self, path: Path, rows: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["value"])
            for index in range(rows):
                writer.writerow([index])

    def _fixture(self, root: Path) -> tuple[Path, Path]:
        work = root / "work"
        version = root / "version"
        (work / "metadata").mkdir(parents=True)
        (version / "registry").mkdir(parents=True)
        (version / "metadata").mkdir(parents=True)
        (version / "xrefs").mkdir(parents=True)

        exe_sha = "e" * 64
        metadata_sha = "m" * 64
        (version / "hashes.json").write_text(
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

        self._write_csv(work / "metadata/types.csv", 2)
        self._write_csv(work / "metadata/fields.csv", 3)
        self._write_csv(work / "metadata/methods.csv", 4)
        self._write_csv(work / "metadata/method-pointers.csv", 4)
        self._write_csv(work / "metadata/runtime-types.csv", 2)
        self._write_csv(work / "getcmdid-candidates.csv", 2)
        self._write_csv(work / "metadata-usage-types.csv", 2)
        self._write_csv(work / "registry-candidate-graph.csv", 2)
        (work / "metadata/type-methods.json").write_text(
            json.dumps({"TYPE": [{"method_index": 0}]}), encoding="utf-8"
        )
        (work / "metadata/native-decoder-summary.json").write_text(
            json.dumps(
                {
                    "sample": {
                        "exe_sha256": exe_sha,
                        "metadata_sha256": metadata_sha,
                    },
                    "counts": {"types": 2, "fields": 3, "methods": 4},
                }
            ),
            encoding="utf-8",
        )
        (work / "metadata/runtime-types.summary.json").write_text(
            json.dumps(
                {
                    "exe_sha256": exe_sha,
                    "anchor_405772_class_84249_DMMJNICDOHM": True,
                }
            ),
            encoding="utf-8",
        )
        (work / "metadata-usage-types.summary.json").write_text(
            json.dumps({"anchor_37523_to_405772_to_84249_DMMJNICDOHM": True}),
            encoding="utf-8",
        )
        (work / "getcmdid-candidates.summary.json").write_text(
            json.dumps(
                {
                    "exe_sha256": exe_sha,
                    "method_rows": 4,
                    "anchor_26105_HJDNCHODGOL_0x10587260": True,
                }
            ),
            encoding="utf-8",
        )
        (work / "registry-candidate-graph.summary.json").write_text(
            json.dumps({"all_preserved_anchors_pass": True}), encoding="utf-8"
        )
        return work, version

    def test_publishes_intermediates_without_faking_canonical_registry(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            work, version = self._fixture(root)
            result = publish_generated_artifacts_71(
                work,
                version,
                expected_counts=(2, 3, 4),
            )

            self.assertFalse(result["canonical_registry_published"])
            self.assertTrue((version / "metadata/types.csv").is_file())
            self.assertTrue((version / "metadata/methods.csv").is_file())
            self.assertTrue((version / "metadata/type-methods.json").is_file())
            self.assertTrue((version / "metadata/runtime-types.csv").is_file())
            self.assertTrue((version / "registry/getcmdid-candidates.csv").is_file())
            self.assertTrue((version / "registry/metadata-usage-types.csv").is_file())
            self.assertTrue((version / "registry/registry-candidate-graph.csv").is_file())
            self.assertFalse((version / "registry/registry.csv").exists())
            self.assertTrue((version / "generated-artifacts.json").is_file())

    def test_rejects_seed_sized_metadata_even_when_summary_claims_full_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            work, version = self._fixture(root)
            # Remove one method row while keeping the summary untouched.
            self._write_csv(work / "metadata/methods.csv", 1)
            with self.assertRaisesRegex(ValueError, "CSV row count mismatch"):
                publish_generated_artifacts_71(
                    work,
                    version,
                    expected_counts=(2, 3, 4),
                )

    def test_optional_xrefs_are_published_only_when_generated(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            work, version = self._fixture(root)
            self._write_csv(work / "xrefs/message-handlers.csv", 1)
            self._write_csv(work / "xrefs/message-senders.csv", 1)

            result = publish_generated_artifacts_71(
                work,
                version,
                expected_counts=(2, 3, 4),
            )

            self.assertIn("xrefs/message-handlers.csv", result["files"])
            self.assertIn("xrefs/message-senders.csv", result["files"])
            self.assertTrue((version / "xrefs/message-handlers.csv").is_file())
            self.assertTrue((version / "xrefs/message-senders.csv").is_file())


if __name__ == "__main__":
    unittest.main()
