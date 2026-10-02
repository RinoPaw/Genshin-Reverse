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

    def _write_table(self, path: Path, fieldnames: list[str], rows: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for index in range(rows):
                row = {field: "" for field in fieldnames}
                if "type_definition_index" in row:
                    row["type_definition_index"] = str(index % 2)
                if "type_name" in row:
                    row["type_name"] = f"TYPE{index % 2}"
                if "method_index" in row:
                    row["method_index"] = str(index)
                if "field_index" in row:
                    row["field_index"] = str(index)
                if "type_index" in row:
                    row["type_index"] = str(index)
                if "rva" in row:
                    row["rva"] = f"0x{0x1000 + index:X}"
                if "va" in row:
                    row["va"] = f"0x{0x140001000 + index:X}"
                if "parameter_types" in row:
                    row["parameter_types"] = "[]"
                if "status" in row:
                    row["status"] = "static-decoded"
                if "evidence" in row:
                    row["evidence"] = "fixture provenance that canonical projection should omit"
                writer.writerow(row)

    def _write_current_registry(self, version: Path) -> None:
        registry = version / "registry"
        registry.mkdir(parents=True, exist_ok=True)
        with (registry / "registry.csv").open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["cmd_id"])
            for cmd_id in range(4896):
                writer.writerow([cmd_id])
        (registry / "registry.summary.json").write_text(
            json.dumps(
                {
                    "row_count": 4896,
                    "unique_cmd_ids": 4896,
                    "strict_slot_type_cmd_bijection": True,
                    "status": "canonical-static-identity-registry",
                }
            ),
            encoding="utf-8",
        )

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

        common_extra = ["status", "evidence"]
        self._write_table(
            work / "metadata/types.csv",
            [
                "type_definition_index", "namespace", "type_name", "parent_type",
                "field_start", "field_count", "method_start", "method_count",
                "name_token", "record_file_offset", *common_extra,
            ],
            2,
        )
        self._write_table(
            work / "metadata/fields.csv",
            [
                "field_index", "type_definition_index", "type_name", "field_name",
                "field_type", "field_type_index", "name_token", "offset",
                "record_file_offset", *common_extra,
            ],
            3,
        )
        self._write_table(
            work / "metadata/methods.csv",
            [
                "method_index", "type_definition_index", "type_name", "method_name",
                "rva", "return_type", "parameter_types", "parameter_start",
                "parameter_count", "name_token", "parameter_type_indices",
                "record_file_offset", *common_extra,
            ],
            4,
        )
        self._write_table(
            work / "metadata/method-pointers.csv",
            ["method_index", "rva", "va", *common_extra],
            4,
        )
        self._write_table(
            work / "metadata/runtime-types.csv",
            [
                "type_index", "kind", "kind_name", "data_u32",
                "type_definition_index", "type_name", "entry_rva", *common_extra,
            ],
            2,
        )
        self._write_csv(work / "getcmdid-candidates.csv", 2)
        self._write_csv(work / "metadata-usage-types.csv", 2)
        self._write_csv(work / "registry-candidate-graph.csv", 2)
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

    def test_publishes_compact_metadata_without_faking_canonical_registry(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            work, version = self._fixture(root)
            result = publish_generated_artifacts_71(work, version, expected_counts=(2, 3, 4))

            self.assertFalse(result["canonical_registry_published"])
            for rel in (
                "metadata/types.csv",
                "metadata/fields.csv",
                "metadata/methods.csv",
                "metadata/method-pointers.csv",
                "metadata/type-methods.json",
                "metadata/runtime-types.csv",
                "registry/getcmdid-candidates.csv",
                "registry/metadata-usage-types.csv",
                "registry/registry-candidate-graph.csv",
            ):
                self.assertTrue((version / rel).is_file(), rel)
            self.assertFalse((version / "registry/registry.csv").exists())
            self.assertEqual(result["files"], result["artifacts"])
            self.assertEqual(result["validation"]["metadata_counts"]["method_pointers"], 4)
            self.assertEqual(result["publication"]["metadata_format"], "compact-query-indexes")

            with (version / "metadata/methods.csv").open("r", encoding="utf-8", newline="") as f:
                header = next(csv.reader(f))
            self.assertNotIn("status", header)
            self.assertNotIn("evidence", header)
            self.assertNotIn("parameter_type_indices", header)

            type_methods = json.loads((version / "metadata/type-methods.json").read_text(encoding="utf-8"))
            self.assertEqual(type_methods["by_type_name"]["TYPE0"], [0, 2])
            self.assertEqual(type_methods["by_type_definition_index"]["1"], [1, 3])

    def test_preserves_current_xref_published_canonical_registry(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            work, version = self._fixture(root)
            self._write_current_registry(version)
            result = publish_generated_artifacts_71(work, version, expected_counts=(2, 3, 4))

            self.assertTrue(result["canonical_registry_published"])
            self.assertTrue((version / "registry/registry.csv").is_file())
            self.assertTrue((version / "registry/registry.summary.json").is_file())
            self.assertFalse((version / "registry/registry.json").exists())
            self.assertFalse((version / "registry/summary.json").exists())

    def test_rejects_half_published_canonical_registry(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            work, version = self._fixture(root)
            self._write_csv(version / "registry/registry.csv", 4896)
            with self.assertRaisesRegex(ValueError, "publication is incomplete"):
                publish_generated_artifacts_71(work, version, expected_counts=(2, 3, 4))

    def test_metadata_publication_does_not_require_registry_heuristics(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            work, version = self._fixture(root)
            for rel in (
                "metadata-usage-types.csv",
                "metadata-usage-types.summary.json",
                "registry-candidate-graph.csv",
                "registry-candidate-graph.summary.json",
            ):
                (work / rel).unlink()

            result = publish_generated_artifacts_71(work, version, expected_counts=(2, 3, 4))
            self.assertTrue((version / "metadata/fields.csv").is_file())
            self.assertTrue((version / "metadata/method-pointers.csv").is_file())
            self.assertNotIn("registry/metadata-usage-types.csv", result["files"])
            self.assertNotIn("registry/registry-candidate-graph.csv", result["files"])
            self.assertEqual(result["validation"]["optional_registry_checks"], {})

    def test_rejects_seed_sized_metadata_even_when_summary_claims_full_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            work, version = self._fixture(root)
            self._write_table(
                work / "metadata/methods.csv",
                [
                    "method_index", "type_definition_index", "type_name", "method_name",
                    "rva", "return_type", "parameter_types", "parameter_start",
                    "parameter_count", "name_token", "parameter_type_indices",
                    "record_file_offset", "status", "evidence",
                ],
                1,
            )
            with self.assertRaisesRegex(ValueError, "CSV row count mismatch"):
                publish_generated_artifacts_71(work, version, expected_counts=(2, 3, 4))

    def test_rejects_incomplete_method_pointer_table(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            work, version = self._fixture(root)
            self._write_table(
                work / "metadata/method-pointers.csv",
                ["method_index", "rva", "va", "status", "evidence"],
                3,
            )
            with self.assertRaisesRegex(ValueError, "method-pointer CSV row count mismatch"):
                publish_generated_artifacts_71(work, version, expected_counts=(2, 3, 4))

    def test_optional_xrefs_are_published_only_when_generated(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            work, version = self._fixture(root)
            self._write_csv(work / "xrefs/message-handlers.csv", 1)
            self._write_csv(work / "xrefs/message-senders.csv", 1)
            result = publish_generated_artifacts_71(work, version, expected_counts=(2, 3, 4))

            self.assertIn("xrefs/message-handlers.csv", result["files"])
            self.assertIn("xrefs/message-senders.csv", result["files"])


if __name__ == "__main__":
    unittest.main()
