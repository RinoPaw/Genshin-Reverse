from __future__ import annotations

import csv
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSION = ROOT / "versions" / "7.1.0-global" / "windows-x64"
ANALYSIS = VERSION / "analyses" / "monster-drowning" / "evidence.json"


class MonsterDrowningStatic71Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads(ANALYSIS.read_text(encoding="utf-8"))
        with (VERSION / "registry" / "registry.csv").open(encoding="utf-8", newline="") as stream:
            cls.registry = {int(row["cmd_id"]): row for row in csv.DictReader(stream)}
        targets = {14990, 60907}
        with (VERSION / "metadata" / "types.csv").open(encoding="utf-8", newline="") as stream:
            cls.types = {
                int(row["type_definition_index"]): row
                for row in csv.DictReader(stream)
                if int(row["type_definition_index"]) in targets
            }

    def test_pinned_client_and_registry_controls(self):
        self.assertEqual(self.evidence["status"], "UNRESOLVED")
        self.assertEqual(len(self.registry), 4896)
        self.assertNotIn(29500, self.registry)

    def test_historical_ids_do_not_pretend_to_be_semantics(self):
        checks = self.evidence["canonical_registry"]["checks"]
        for item in checks:
            opcode = item.get("historical_opcode", item.get("server_opcode"))
            with self.subTest(cmd_id=opcode):
                if not item["in_registry"]:
                    self.assertNotIn(opcode, self.registry)
                    self.assertEqual(item["disposition"], "REJECTED_FOR_7_1")
                    continue
                actual = self.registry[opcode]
                self.assertEqual(actual["type_name"], item["type_name"])
                self.assertEqual(int(actual["type_definition_index"]), item["type_definition_index"])
                self.assertFalse(actual["semantic_name"])
                definition = self.types[item["type_definition_index"]]
                self.assertEqual(int(definition["field_count"]), item["metadata_declared_field_count"])
                self.assertNotEqual(item["disposition"], "CONFIRMED")

    def test_historical_field_numbers_are_separated(self):
        historical = self.evidence["crosscheck"]["historical_proto_shapes"]
        self.assertEqual(historical[0]["fields"][0]["number"], 3)
        self.assertEqual([f["number"] for f in historical[1]["fields"]], [4, 13])
        self.assertEqual(self.evidence["crosscheck"]["shape_status"], "HISTORICAL_COMPATIBILITY_ONLY")
        self.assertEqual(len(self.evidence["next_evidence_gate"]), 3)


if __name__ == "__main__":
    unittest.main()
