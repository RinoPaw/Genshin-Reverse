from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from genshinre.artifactpublish import publish_generated_artifacts_71
from genshinre.nativeprofile import PROFILE_71
from genshinre.registry import CANONICAL_REGISTRY_COLUMNS

EXPECTED_RUNTIME_TYPE_COUNT = PROFILE_71.runtime_type_count


class ArtifactPublishTests(unittest.TestCase):
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
                    row["evidence"] = "fixture provenance"
                writer.writerow(row)

    def _write_current_registry(self, version: Path) -> None:
        registry = version / "registry"
        registry.mkdir(parents=True, exist_ok=True)
        with (registry / "registry.csv").open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CANONICAL_REGISTRY_COLUMNS)
            writer.writeheader()
            for cmd_id in range(4896):
                row = {column: "" for column in CANONICAL_REGISTRY_COLUMNS}
                row["cmd_id"] = str(cmd_id)
                writer.writerow(row)
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
        (version / "metadata").mkdir(parents=True)
        (version / "xrefs").mkdir(parents=True)

        exe_sha = "e" * 64
        metadata_sha = "d" * 64
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
        self._write_current_registry(version)

        common_extra = ["status", "evidence"]
        self._write_table(
            work / "metadata/types.csv",
            [
                "type_definition_index",
                "namespace",
                "type_name",
                "parent_type",
                "field_start",
                "field_count",
                "method_start",
                "method_count",
                "name_token",
                "record_file_offset",
                *common_extra,
            ],
            2,
        )
        self._write_table(
            work / "metadata/fields.csv",
            [
                "field_index",
                "type_definition_index",
                "type_name",
                "field_name",
                "field_type",
                "field_type_index",
                "name_token",
                "offset",
                "record_file_offset",
                *common_extra,
            ],
            3,
        )
        self._write_table(
            work / "metadata/methods.csv",
            [
                "method_index",
                "type_definition_index",
                "type_name",
                "method_name",
                "rva",
                "return_type",
                "parameter_types",
                "parameter_start",
                "parameter_count",
                "name_token",
                "parameter_type_indices",
                "record_file_offset",
                *common_extra,
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
                "type_index",
                "kind",
                "kind_name",
                "data_u32",
                "type_definition_index",
                "type_name",
                "entry_rva",
                *common_extra,
            ],
            2,
        )
        self._write_table(work / "getcmdid-candidates.csv", ["value"], 2)

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
                    "status": "canonical-exact-runtime-type-index",
                    "runtime_type_count": EXPECTED_RUNTIME_TYPE_COUNT,
                    "type_array_rva": "0x1000",
                    "boundary_rva": "0xA6F360",
                    "boundary_entry_hex": "8988883b0000000060da9e4501000000",
                    "boundary_entry_valid_type": False,
                    "structural_validation_passed": True,
                    "emitted_rows": 2,
                    "named_definition_entries": 2,
                    "anchor_405772_class_84249_DMMJNICDOHM": True,
                }
            ),
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
        return work, version

    def test_publishes_only_canonical_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            work, version = self._fixture(Path(td))
            self._write_table(work / "control-set.csv", ["cmd_id"], 1)
            self._write_table(work / "xrefs/message-senders.csv", ["cmd_id"], 1)

            result = publish_generated_artifacts_71(
                work, version, expected_counts=(2, 3, 4)
            )

            self.assertEqual(result["manifest_version"], 4)
            self.assertTrue(result["canonical_registry_published"])
            self.assertEqual(result["validation"]["runtime_type_count"], 683_574)
            self.assertEqual(result["validation"]["runtime_type_boundary_rva"], "0xA6F360")
            self.assertTrue(result["validation"]["runtime_type_boundary_verified"])
            self.assertNotIn("optional_artifacts_published", result)
            self.assertNotIn("optional_registry_checks", result["validation"])

            for rel in (
                "metadata/types.csv",
                "metadata/fields.csv",
                "metadata/methods.csv",
                "metadata/method-pointers.csv",
                "metadata/type-methods.json",
                "metadata/runtime-types.csv",
                "metadata/native-decoder-summary.json",
                "metadata/runtime-types.summary.json",
                "registry/getcmdid-candidates.csv",
                "registry/getcmdid-candidates.summary.json",
            ):
                self.assertTrue((version / rel).is_file(), rel)
                self.assertIn(rel, result["artifacts"])

            self.assertFalse((version / "registry/control-set.csv").exists())
            self.assertFalse((version / "xrefs/message-senders.csv").exists())

            with (version / "metadata/methods.csv").open(
                "r", encoding="utf-8", newline=""
            ) as f:
                header = next(csv.reader(f))
            self.assertNotIn("status", header)
            self.assertNotIn("evidence", header)
            self.assertNotIn("parameter_type_indices", header)

            type_methods = json.loads(
                (version / "metadata/type-methods.json").read_text(encoding="utf-8")
            )
            self.assertEqual(type_methods["by_type_name"]["TYPE0"], [0, 2])
            self.assertEqual(type_methods["by_type_definition_index"]["1"], [1, 3])

    def test_requires_current_canonical_registry(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            work, version = self._fixture(Path(td))
            (version / "registry/registry.csv").unlink()
            (version / "registry/registry.summary.json").unlink()
            with self.assertRaisesRegex(ValueError, "current canonical registry is required"):
                publish_generated_artifacts_71(work, version, expected_counts=(2, 3, 4))

    def test_rejects_noncanonical_registry_header(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            work, version = self._fixture(Path(td))
            self._write_table(version / "registry/registry.csv", ["cmd_id"], 4896)
            with self.assertRaisesRegex(ValueError, "canonical registry CSV header mismatch"):
                publish_generated_artifacts_71(work, version, expected_counts=(2, 3, 4))

    def test_rejects_seed_sized_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            work, version = self._fixture(Path(td))
            self._write_table(
                work / "metadata/methods.csv",
                [
                    "method_index",
                    "type_definition_index",
                    "type_name",
                    "method_name",
                    "rva",
                    "return_type",
                    "parameter_types",
                    "parameter_start",
                    "parameter_count",
                    "name_token",
                    "parameter_type_indices",
                    "record_file_offset",
                    "status",
                    "evidence",
                ],
                1,
            )
            with self.assertRaisesRegex(ValueError, "CSV row count mismatch"):
                publish_generated_artifacts_71(work, version, expected_counts=(2, 3, 4))

    def test_rejects_incomplete_method_pointer_table(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            work, version = self._fixture(Path(td))
            self._write_table(
                work / "metadata/method-pointers.csv",
                ["method_index", "rva", "va", "status", "evidence"],
                3,
            )
            with self.assertRaisesRegex(ValueError, "method-pointer CSV row count mismatch"):
                publish_generated_artifacts_71(work, version, expected_counts=(2, 3, 4))

    def test_rejects_runtime_sample_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            work, version = self._fixture(Path(td))
            summary = work / "metadata/runtime-types.summary.json"
            data = json.loads(summary.read_text(encoding="utf-8"))
            data["exe_sha256"] = "0" * 64
            summary.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "runtime type index EXE hash"):
                publish_generated_artifacts_71(work, version, expected_counts=(2, 3, 4))

    def test_rejects_runtime_count_drift(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            work, version = self._fixture(Path(td))
            summary = work / "metadata/runtime-types.summary.json"
            data = json.loads(summary.read_text(encoding="utf-8"))
            data["runtime_type_count"] = EXPECTED_RUNTIME_TYPE_COUNT - 1
            summary.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "runtime type count"):
                publish_generated_artifacts_71(work, version, expected_counts=(2, 3, 4))

    def test_rejects_runtime_boundary_drift(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            work, version = self._fixture(Path(td))
            summary = work / "metadata/runtime-types.summary.json"
            data = json.loads(summary.read_text(encoding="utf-8"))
            data["boundary_rva"] = "0xA6F370"
            summary.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError, r"type_array_rva \+ runtime_type_count \* 16"
            ):
                publish_generated_artifacts_71(work, version, expected_counts=(2, 3, 4))

    def test_rejects_runtime_structural_gate_loss(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            work, version = self._fixture(Path(td))
            summary = work / "metadata/runtime-types.summary.json"
            data = json.loads(summary.read_text(encoding="utf-8"))
            data["structural_validation_passed"] = False
            summary.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "complete structural validation"):
                publish_generated_artifacts_71(work, version, expected_counts=(2, 3, 4))

    def test_rejects_runtime_csv_summary_row_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            work, version = self._fixture(Path(td))
            summary = work / "metadata/runtime-types.summary.json"
            data = json.loads(summary.read_text(encoding="utf-8"))
            data["emitted_rows"] = 3
            data["named_definition_entries"] = 3
            summary.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "runtime type CSV row count"):
                publish_generated_artifacts_71(work, version, expected_counts=(2, 3, 4))


if __name__ == "__main__":
    unittest.main()
