from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from genshinre.validate import (
    ANALYSIS_STATUSES,
    MESSAGE_DIRECTIONS,
    PROTOBUF_WIRE_TYPES,
    _validate_message_shapes,
)


class MessageShapesContractTests(unittest.TestCase):
    def _validate(self, data: object) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "message-shapes.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            errors: list[str] = []
            _validate_message_shapes(path, errors)
            return errors

    def test_committed_message_shapes_pass_contract(self) -> None:
        path = (
            Path(__file__).resolve().parents[1]
            / "versions"
            / "7.1.0-global"
            / "windows-x64"
            / "proto"
            / "message-shapes.json"
        )
        errors: list[str] = []
        _validate_message_shapes(path, errors)
        self.assertEqual([], errors)

    def test_rejects_duplicate_cmd_and_field_numbers(self) -> None:
        errors = self._validate(
            {
                "One": {
                    "cmd_id": 10,
                    "direction": "C2S",
                    "status": "UNRESOLVED",
                    "fields": [
                        {"number": 1, "wire_type": 0},
                        {"number": 1, "wire_type": 2},
                    ],
                },
                "Two": {
                    "cmd_id": 10,
                    "direction": "S2C",
                    "status": "CONFIRMED",
                    "fields": [],
                },
            }
        )
        self.assertTrue(any("duplicate cmd_id 10" in error for error in errors))
        self.assertTrue(any("duplicate field number 1" in error for error in errors))

    def test_rejects_invalid_wire_type_and_partial_hex_byte(self) -> None:
        errors = self._validate(
            {
                "Bad": {
                    "cmd_id": 11,
                    "direction": "unknown",
                    "status": "CANDIDATE",
                    "observed_payload_hex": "abc",
                    "fields": [{"number": 2, "wire_type": 6}],
                }
            }
        )
        self.assertTrue(any("whole-byte hex" in error for error in errors))
        self.assertTrue(any("invalid protobuf wire type" in error for error in errors))

    def test_schema_enums_match_validator_contract(self) -> None:
        schema_path = Path(__file__).resolve().parents[1] / "schemas" / "message-shapes.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        defs = schema["$defs"]

        self.assertEqual(ANALYSIS_STATUSES, set(defs["status"]["enum"]))
        self.assertEqual(
            MESSAGE_DIRECTIONS,
            set(defs["message"]["properties"]["direction"]["enum"]),
        )
        self.assertEqual(
            PROTOBUF_WIRE_TYPES,
            set(defs["field"]["properties"]["wire_type"]["enum"]),
        )


if __name__ == "__main__":
    unittest.main()
