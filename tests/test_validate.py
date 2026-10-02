from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from genshinre.artifactmanifest import REQUIRED_PUBLICATION_ROWS
from genshinre.registry import CANONICAL_REGISTRY_COLUMNS
from genshinre.validate import _validate_generated_artifacts, _validate_known_opcodes


class ValidatorIntegrationTests(unittest.TestCase):
    def _write_manifest(
        self,
        root: Path,
        *,
        canonical_registry_published: bool,
    ) -> None:
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

        (root / "generated-artifacts.json").write_text(
            json.dumps(
                {
                    "manifest_version": 3,
                    "source": "genshinre.artifactpublish",
                    "status": "generated-artifacts-published",
                    "canonical_registry_published": canonical_registry_published,
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
                        "getcmdid_anchor": True,
                    },
                    "publication": {
                        "metadata_format": "compact-query-indexes",
                        "metadata_rows": {
                            rel: 1 for rel in REQUIRED_PUBLICATION_ROWS
                        },
                    },
                    "artifacts": list(REQUIRED_PUBLICATION_ROWS),
                }
            ),
            encoding="utf-8",
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

    def _write_known_opcodes(self, root: Path, rows: list[dict[str, str]]) -> Path:
        proto = root / "proto"
        proto.mkdir(exist_ok=True)
        path = proto / "known-opcodes.csv"
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=(
                    "semantic_name",
                    "cmd_id",
                    "direction",
                    "status",
                    "evidence",
                    "notes",
                ),
            )
            writer.writeheader()
            writer.writerows(rows)
        return path

    def test_manifest_v3_runs_through_current_main_validator(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_canonical_registry(root)
            self._write_manifest(root, canonical_registry_published=True)

            errors: list[str] = []
            warnings: list[str] = []
            _validate_generated_artifacts(
                root, errors, warnings, allow_partial=False
            )

            self.assertEqual([], errors)
            self.assertEqual([], warnings)

    def test_registry_publication_flag_requires_registry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_manifest(root, canonical_registry_published=True)

            errors: list[str] = []
            _validate_generated_artifacts(
                root, errors, [], allow_partial=False
            )

            self.assertTrue(
                any("canonical_registry_published is true" in error for error in errors)
            )

    def test_registry_summary_must_match_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_canonical_registry(root)
            summary_path = root / "registry" / "registry.summary.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            summary["row_count"] = 2
            summary_path.write_text(json.dumps(summary), encoding="utf-8")
            self._write_manifest(root, canonical_registry_published=True)

            errors: list[str] = []
            _validate_generated_artifacts(
                root, errors, [], allow_partial=False
            )

            self.assertTrue(
                any("row_count does not match registry.csv" in error for error in errors)
            )

    def test_known_opcodes_reject_non_confirmed_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_canonical_registry(root)
            known_path = self._write_known_opcodes(
                root,
                [
                    {
                        "semantic_name": "KnownReq",
                        "cmd_id": "1",
                        "direction": "C2S",
                        "status": "CANDIDATE",
                        "evidence": "unit test",
                        "notes": "",
                    }
                ],
            )

            errors: list[str] = []
            _validate_known_opcodes(known_path, root / "registry" / "registry.csv", errors)

            self.assertTrue(any("must be CONFIRMED" in error for error in errors))

    def test_known_opcodes_must_match_registry_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_canonical_registry(root)
            known_path = self._write_known_opcodes(
                root,
                [
                    {
                        "semantic_name": "KnownReq",
                        "cmd_id": "1",
                        "direction": "C2S",
                        "status": "CONFIRMED",
                        "evidence": "unit test",
                        "notes": "",
                    }
                ],
            )

            errors: list[str] = []
            _validate_known_opcodes(known_path, root / "registry" / "registry.csv", errors)

            self.assertTrue(any("semantic_name does not match" in error for error in errors))

    def test_canonical_registry_cannot_keep_semantics_missing_from_known_opcodes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_canonical_registry(root)
            known_path = self._write_known_opcodes(root, [])

            errors: list[str] = []
            _validate_known_opcodes(known_path, root / "registry" / "registry.csv", errors)

            self.assertTrue(
                any("canonical semantic enrichment does not match" in error for error in errors)
            )


if __name__ == "__main__":
    unittest.main()
