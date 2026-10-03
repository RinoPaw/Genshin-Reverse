from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from genshinre.scenehandlerartifact import validate_scene_handler_dispatch


class SceneHandlerArtifactTests(unittest.TestCase):
    def _fixture(self, root: Path) -> Path:
        version = root / "version"
        analysis = version / "analyses" / "scene-handler-dispatch"
        analysis.mkdir(parents=True)
        (version / "registry").mkdir(parents=True)

        exe_sha = "a" * 64
        (version / "hashes.json").write_text(
            json.dumps(
                {
                    "samples": {
                        "GenshinImpact.exe": {"sha256": exe_sha},
                    }
                }
            ),
            encoding="utf-8",
        )
        with (version / "registry" / "registry.csv").open(
            "w", encoding="utf-8", newline=""
        ) as f:
            writer = csv.DictWriter(f, fieldnames=["cmd_id", "type_name"])
            writer.writeheader()
            writer.writerow({"cmd_id": "36641", "type_name": "NCBEHBOCBJJ"})

        with (analysis / "scene-handler-slots.csv").open(
            "w", encoding="utf-8", newline=""
        ) as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "slots",
                    "cmd_id",
                    "type_name",
                    "method_name",
                    "method_index",
                    "method_position",
                    "method_rva",
                    "method_size",
                    "hit_count",
                ],
            )
            writer.writeheader()
            writer.writerow(
                {
                    "slots": "0x4B2A90",
                    "cmd_id": "36641",
                    "type_name": "NCBEHBOCBJJ",
                    "method_name": "GDILHLIGMPI",
                    "method_index": "615758",
                    "method_position": "6",
                    "method_rva": "0xF045790",
                    "method_size": "112",
                    "hit_count": "1",
                }
            )
        (analysis / "README.md").write_text("# fixture\n", encoding="utf-8")
        (analysis / "evidence.json").write_text(
            json.dumps(
                {
                    "topic": "scene-handler-dispatch",
                    "owner_type": "KLLNGCPBLMM",
                    "exact_sample": {"GenshinImpact.exe_sha256": exe_sha},
                    "provenance": {
                        "workflow_run_id": 1,
                        "workflow_head_sha": "b" * 40,
                        "artifact_id": 2,
                        "artifact_digest": "sha256:" + "c" * 64,
                    },
                    "scan_summary": {
                        "method_row_count": 1,
                        "instruction_hit_count": 1,
                        "unique_slot_count": 1,
                        "destination_register_counts": {"rcx": 1},
                        "base_register_counts": {"rax": 1},
                    },
                    "controls": [
                        {
                            "slot": "0x4B2A90",
                            "cmd_id": 36641,
                            "type_name": "NCBEHBOCBJJ",
                            "method_index": 615758,
                            "method_rva": "0xF045790",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return version

    def test_committed_71_artifact_is_consistent(self) -> None:
        version = (
            Path(__file__).resolve().parents[1]
            / "versions"
            / "7.1.0-global"
            / "windows-x64"
        )
        self.assertEqual([], validate_scene_handler_dispatch(version))

    def test_valid_fixture_passes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            version = self._fixture(Path(td))
            self.assertEqual([], validate_scene_handler_dispatch(version))

    def test_rejects_count_drift(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            version = self._fixture(Path(td))
            evidence_path = (
                version / "analyses" / "scene-handler-dispatch" / "evidence.json"
            )
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            evidence["scan_summary"]["instruction_hit_count"] = 2
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

            errors = validate_scene_handler_dispatch(version)
            self.assertTrue(any("hit count does not match" in error for error in errors))

    def test_rejects_registry_identity_drift(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            version = self._fixture(Path(td))
            registry_path = version / "registry" / "registry.csv"
            registry_path.write_text(
                "cmd_id,type_name\n36641,OTHER_TYPE\n",
                encoding="utf-8",
            )

            errors = validate_scene_handler_dispatch(version)
            self.assertTrue(any("absent from canonical registry" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
