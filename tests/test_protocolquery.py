from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from genshinre.protocolquery import query_protocol
from genshinre.registry import CANONICAL_REGISTRY_COLUMNS


class ProtocolQueryTests(unittest.TestCase):
    def _write_csv(self, path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    def test_joins_protocol_evidence_by_cmd_id(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            registry_row = {column: "" for column in CANONICAL_REGISTRY_COLUMNS}
            registry_row.update(
                {
                    "index": "48",
                    "cmd_id": "186",
                    "type_name": "NLOMEGMJDGJ",
                    "type_definition_index": "61556",
                    "direction": "C2S",
                    "type_slot_rva": "0x57F3858",
                    "get_cmd_id_rva": "0x9ED2160",
                    "status": "static-verified-identity",
                    "evidence": "fixture",
                }
            )
            self._write_csv(
                root / "registry" / "registry.csv",
                list(CANONICAL_REGISTRY_COLUMNS),
                [registry_row],
            )
            self._write_csv(
                root / "metadata" / "fields.csv",
                ["field_index", "type_definition_index", "type_name", "field_name", "field_type", "field_type_index"],
                [
                    {
                        "field_index": "1",
                        "type_definition_index": "61556",
                        "type_name": "NLOMEGMJDGJ",
                        "field_name": "DCCONFODELK",
                        "field_type": "kind_0x15",
                        "field_type_index": "476942",
                    }
                ],
            )
            self._write_csv(
                root / "metadata" / "methods.csv",
                ["method_index", "type_definition_index", "type_name", "method_name", "method_rva", "parameter_types"],
                [
                    {
                        "method_index": "2",
                        "type_definition_index": "61556",
                        "type_name": "NLOMEGMJDGJ",
                        "method_name": "IENGFLPCLNM",
                        "method_rva": "0x9ED2100",
                        "parameter_types": '["EIBJNHDPEMB"]',
                    }
                ],
            )
            self._write_csv(
                root / "xrefs" / "message-senders.csv",
                ["cmd_id", "type_name", "sender_type", "sender_method", "sender_rva", "context", "status", "evidence"],
                [
                    {
                        "cmd_id": "186",
                        "type_name": "NLOMEGMJDGJ",
                        "sender_type": "",
                        "sender_method": "",
                        "sender_rva": "0x1000",
                        "context": "fixture",
                        "status": "CANDIDATE",
                        "evidence": "fixture",
                    }
                ],
            )
            self._write_csv(
                root / "cmdids" / "observations.csv",
                ["name", "cmd_id", "direction", "status", "evidence"],
                [
                    {
                        "name": "UNKNOWN_186",
                        "cmd_id": "186",
                        "direction": "C2S",
                        "status": "UNRESOLVED",
                        "evidence": "runtime fixture",
                    }
                ],
            )
            self._write_csv(
                root / "proto" / "known-opcodes.csv",
                ["semantic_name", "cmd_id", "direction", "status", "evidence", "notes"],
                [],
            )
            (root / "proto" / "message-shapes.json").write_text("{}\n", encoding="utf-8")

            result = query_protocol(root, cmd_id=186)

            self.assertEqual(result["result_count"], 1)
            item = result["results"][0]
            self.assertEqual(item["registry"]["type_name"], "NLOMEGMJDGJ")
            self.assertEqual(item["counts"]["fields"], 1)
            self.assertEqual(item["counts"]["methods"], 1)
            self.assertEqual(item["counts"]["senders"], 1)
            self.assertEqual(item["counts"]["runtime_observations"], 1)
            self.assertEqual(item["metadata"]["methods"][0]["parameter_types"], ["EIBJNHDPEMB"])

    def test_supports_type_definition_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            row = {column: "" for column in CANONICAL_REGISTRY_COLUMNS}
            row.update(
                {
                    "index": "1",
                    "cmd_id": "7",
                    "type_name": "TYPE7",
                    "type_definition_index": "99",
                    "status": "static-verified-identity",
                }
            )
            self._write_csv(root / "registry" / "registry.csv", list(CANONICAL_REGISTRY_COLUMNS), [row])
            result = query_protocol(root, type_definition_index=99)
            self.assertEqual(result["result_count"], 1)
            self.assertEqual(result["results"][0]["registry"]["cmd_id"], "7")


if __name__ == "__main__":
    unittest.main()
