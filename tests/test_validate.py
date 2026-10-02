from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from genshinre.registry import CANONICAL_REGISTRY_COLUMNS
from genshinre.validate import _validate_generated_artifacts, _validate_known_opcodes


class ValidatorIntegrationTests(unittest.TestCase):
    def _write_manifest(
        self,
        root: Path,
        *,
        canonical_registry_published: bool,
        artifacts: list[str] | None = None,
        optional_artifacts_published: list[str] | None = None,
    ) -> None:
        data: dict[str, object] = {
            "manifest_version": 2,
            "canonical_registry_published": canonical_registry_published,
            "artifacts": artifacts or [],
            "optional_artifacts_published": optional_artifacts_published or [],
        }
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

    def test_manifest_v2_runs_through_current_main_validator(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_canonical_registry(root)
            self._write_manifest(
                root,
                canonical_registry_published=True,
                artifacts=[],
                optional_artifacts_published=[],
            )

            errors: list[str] = []
            warnings: list[str] = []
            _validate_generated_artifacts(root, errors, warnings)

            self.assertEqual([], errors)
            self.assertEqual([], warnings)

    def test_registry_publication_flag_requires_registry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_manifest(root, canonical_registry_published=True)

            errors: list[str] = []
            _validate_generated_artifacts(root, errors, [])

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
            _validate_generated_artifacts(root, errors, [])

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
