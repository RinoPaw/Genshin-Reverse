from __future__ import annotations

import json
import unittest
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71

ANALYSIS = (
    Path(__file__).resolve().parents[1]
    / "versions/7.1.0-global/windows-x64/analyses/amber-pause-ack"
)


def load(name: str) -> dict:
    return json.loads((ANALYSIS / name).read_text(encoding="utf-8"))


class AmberPauseEvidenceTests(unittest.TestCase):
    def test_native_probe_is_pinned_to_canonical_executable(self) -> None:
        probe = load("native-probe.json")
        self.assertEqual(PROFILE_71.exe_sha256, probe["verified_exe_sha256"])
        self.assertEqual(PROFILE_71.metadata_sha256, probe["sample"]["metadata_sha256"])

    def test_bool_request_uses_exact_registry_identity_and_field_11(self) -> None:
        probe = load("native-probe.json")
        registry = probe["request_registry"]
        self.assertEqual("5963", registry["cmd_id"])
        self.assertEqual("GLIHKBGFALC", registry["type_name"])
        self.assertEqual("50277", registry["type_definition_index"])
        self.assertEqual("0x57F5160", registry["type_slot_rva"])
        self.assertEqual(["bool"], [field["field_type"] for field in probe["request_fields"]])
        tag = [insn for insn in probe["request_parser_disassembly"]
               if insn["rva"] == "0xA58066E"]
        self.assertEqual(1, len(tag))
        self.assertIn("0x58", tag[0]["op_str"])

    def test_three_independent_send_callers_are_preserved(self) -> None:
        probe = load("native-probe.json")
        hits = probe["request_sender_call_xrefs"]["0x7262BC0"]
        self.assertEqual({"0xC237E10", "0xC252D1F", "0x12E27057"},
                         {hit["instruction_rva"] for hit in hits})
        self.assertEqual({"LLCGIEDMIIG", "Miscs"},
                         {method["type_name"] for method in probe["request_sender_callers"]})
        self.assertEqual({"1307", "20114"},
                         {row["cmd_id"] for row in probe["caller_input_registry"]})

    def test_historical_candidate_remains_distinct(self) -> None:
        probe = load("native-probe.json")
        historical = probe["historical_response_registry_row_not_semantic"]
        self.assertEqual("2870", historical["cmd_id"])
        self.assertEqual("DKPJBENLNFD", historical["type_name"])
        self.assertEqual(5, len(probe["historical_response_fields_not_semantic"]))
        self.assertEqual(
            {"CONFIRMED", "REJECTED", "UNRESOLVED"},
            {claim["status"] for claim in load("evidence.json")["claims"]},
        )


if __name__ == "__main__":
    unittest.main()
