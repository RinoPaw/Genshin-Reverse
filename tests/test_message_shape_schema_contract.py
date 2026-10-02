from __future__ import annotations

import json
import unittest
from pathlib import Path

from genshinre.validate import ANALYSIS_STATUSES, MESSAGE_DIRECTIONS, PROTOBUF_WIRE_TYPES


class MessageShapeSchemaContractTests(unittest.TestCase):
    def test_schema_enums_match_runtime_validator(self) -> None:
        root = Path(__file__).resolve().parents[1]
        schema = json.loads((root / "schemas/message-shapes.schema.json").read_text(encoding="utf-8"))

        defs = schema["$defs"]
        self.assertEqual(set(defs["status"]["enum"]), ANALYSIS_STATUSES)
        self.assertEqual(
            set(defs["message"]["properties"]["direction"]["enum"]),
            MESSAGE_DIRECTIONS,
        )
        self.assertEqual(
            set(defs["field"]["properties"]["wire_type"]["enum"]),
            PROTOBUF_WIRE_TYPES,
        )

    def test_schema_ranges_match_validator_contract(self) -> None:
        root = Path(__file__).resolve().parents[1]
        schema = json.loads((root / "schemas/message-shapes.schema.json").read_text(encoding="utf-8"))
        defs = schema["$defs"]

        cmd_id = defs["message"]["properties"]["cmd_id"]
        self.assertEqual((cmd_id["minimum"], cmd_id["maximum"]), (0, 65535))

        field_number = defs["field"]["properties"]["number"]
        self.assertEqual((field_number["minimum"], field_number["maximum"]), (1, 536870911))


if __name__ == "__main__":
    unittest.main()
