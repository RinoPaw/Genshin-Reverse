from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from genshinre.protocolquery import query_protocol
from genshinre.registry import CANONICAL_REGISTRY_COLUMNS


class ProtocolQuerySceneHandlerTests(unittest.TestCase):
    def _write_csv(
        self,
        path: Path,
        fieldnames: list[str],
        rows: list[dict[str, str]],
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    def test_joins_scene_handler_dispatch_without_promoting_handler_xref(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            registry_row = {column: "" for column in CANONICAL_REGISTRY_COLUMNS}
            registry_row.update(
                {
                    "index": "10",
                    "cmd_id": "36641",
                    "type_name": "NCBEHBOCBJJ",
                    "type_definition_index": "100",
                    "status": "static-verified-identity",
                }
            )
            self._write_csv(
                root / "registry" / "registry.csv",
                list(CANONICAL_REGISTRY_COLUMNS),
                [registry_row],
            )
            self._write_csv(
                root
                / "analyses"
                / "scene-handler-dispatch"
                / "scene-handler-slots.csv",
                [
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
                [
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
                ],
            )
            evidence = (
                root / "analyses" / "scene-handler-dispatch" / "evidence.json"
            )
            evidence.write_text("{}\n", encoding="utf-8")

            result = query_protocol(root, cmd_id=36641)

            self.assertEqual(1, result["result_count"])
            item = result["results"][0]
            dispatch = item["scene_handler_dispatch"]
            self.assertEqual(
                "analyses/scene-handler-dispatch/scene-handler-slots.csv",
                dispatch["source_path"],
            )
            self.assertEqual(
                "analyses/scene-handler-dispatch/evidence.json",
                dispatch["evidence_path"],
            )
            self.assertEqual(1, len(dispatch["rows"]))
            self.assertEqual("0x4B2A90", dispatch["rows"][0]["slots"])
            self.assertEqual("GDILHLIGMPI", dispatch["rows"][0]["method_name"])
            self.assertEqual(1, item["counts"]["scene_handler_dispatch_rows"])
            self.assertEqual([], item["xrefs"]["handlers"])

    def test_missing_scene_handler_artifact_is_empty_layer(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            registry_row = {column: "" for column in CANONICAL_REGISTRY_COLUMNS}
            registry_row.update(
                {
                    "index": "0",
                    "cmd_id": "1",
                    "type_name": "TYPE1",
                    "type_definition_index": "1",
                    "status": "static-verified-identity",
                }
            )
            self._write_csv(
                root / "registry" / "registry.csv",
                list(CANONICAL_REGISTRY_COLUMNS),
                [registry_row],
            )

            item = query_protocol(root, cmd_id=1)["results"][0]
            self.assertEqual(
                {"source_path": None, "evidence_path": None, "rows": []},
                item["scene_handler_dispatch"],
            )
            self.assertEqual(0, item["counts"]["scene_handler_dispatch_rows"])


if __name__ == "__main__":
    unittest.main()
