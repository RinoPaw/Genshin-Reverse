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

    def test_confirmed_request_shape_matches_native_7_1_serializer(self) -> None:
        shapes_file = ANALYSIS.parents[1] / "proto" / "message-shapes.json"
        shapes = json.loads(shapes_file.read_text(encoding="utf-8"))
        request = shapes["PlayerSetPauseReq"]
        self.assertEqual(5963, request["cmd_id"])
        self.assertEqual("C2S", request["direction"])
        self.assertEqual("CONFIRMED", request["status"])
        self.assertEqual(
            [{"number": 11, "wire_type": 0, "likely_type": "bool", "semantic": "is_paused"}],
            request["fields"],
        )

    def test_server_descriptor_is_not_native_response_identity(self) -> None:
        crosscheck = load("astaps-descriptor-crosscheck.json")
        self.assertEqual("SERVER_DESCRIPTOR_ONLY", crosscheck["status"])
        self.assertEqual(
            "dfc0fe457558b86d661b24f0c0ac023a39bbbc37b95a35e603deb4c7efbedfa5",
            crosscheck["source"]["sha256"],
        )
        req = crosscheck["messages"]["PlayerSetPauseReq"]
        rsp = crosscheck["messages"]["PlayerSetPauseRsp"]
        self.assertEqual(11, req["fields"][0]["number"])
        self.assertEqual(4, rsp["fields"][0]["number"])
        self.assertIn("UNRESOLVED", rsp["match_to_exact_client"])

    def test_field4_receiver_candidates_do_not_claim_pause_ack_semantics(self) -> None:
        report = load("field4-receiver-candidates.json")
        self.assertEqual(PROFILE_71.exe_sha256, report["sample_sha256"])
        self.assertEqual("CANDIDATE_ONLY", report["status"])
        self.assertEqual({"22120", "24380"}, set(report["candidates"]))
        for candidate in report["candidates"].values():
            self.assertEqual("UNRESOLVED", candidate["semantic_status"])
            self.assertFalse(candidate["success_direct_pause_state_write"])
            self.assertEqual("int3", candidate["instructions"][-1]["mnemonic"])

    def test_talk_response_native_wire_tags_match_7_1_descriptor(self) -> None:
        data = load("posttalk-response-wire-crosscheck.json")
        self.assertEqual(PROFILE_71.exe_sha256, data["sample"]["exe_sha256"])
        for name, cmd, expected in [
            ("NpcTalkRsp", 3514, {5, 7, 8, 13}),
            ("QuestDestroyNpcRsp", 3992, {9, 13, 15}),
        ]:
            row = data["responses"][name]
            self.assertEqual(cmd, row["cmd_id"])
            self.assertEqual(expected, {field["number"] for field in row["server_fields"]})
            self.assertEqual(expected, {int(tag, 16) >> 3 for tag in row["native_tags"]})
            self.assertEqual("ALL_FIELDS_AND_WIRE_NUMBERS_MATCH", row["match"])
        self.assertIs(False, data["stuck_vs_reconnect"]["reconnect_20_09_32"]["player_time_notify_paused"])
        self.assertEqual(1, data["stuck_vs_reconnect"]["reconnect_20_09_32"]["player_set_pause_req_false"])
        self.assertEqual(
            "dropped on server (unknown 7.1 response CmdId)",
            data["stuck_vs_reconnect"]["reconnect_20_09_32"]["player_set_pause_rsp"],
        )
        claims = {
            item["id"]: item["status"] for item in load("evidence.json")["claims"]
        }
        self.assertEqual("CONFIRMED", claims["npc-talk-and-destroy-response-wire-crosscheck"])
        self.assertEqual("UNRESOLVED", claims["npc-destroy-rsp-client-callback"])

    def test_interaction_27447_is_native_confirmed_without_causality_claim(self) -> None:
        record = load("posttalk-interaction-27447.json")
        self.assertEqual(PROFILE_71.exe_sha256, record["sample"]["exe_sha256"])
        self.assertEqual(
            "STRUCTURAL_CONFIRMED_SEMANTIC_UNRESOLVED", record["status"]
        )
        self.assertEqual(27447, record["registry"]["cmd_id"])
        self.assertEqual("NDAJDBCBAAE", record["registry"]["type_name"])
        self.assertEqual(7, record["wire"]["fields"][0]["field_number"])
        self.assertEqual("0x38", record["wire"]["fields"][0]["serializer_tag"])
        calls = {item["method"]: item["bool_arg"] for item in record["sender_callers"]}
        self.assertTrue(calls["InteractionManager.OnCreateTalkFinish"])
        self.assertFalse(calls["InteractionManager.ClearOnDisconnect"])
        self.assertFalse(calls["InteractionManager.ResumeGameTime"])
        self.assertFalse(calls["InteractionManager.ClearAll"])
        self.assertFalse(calls["InteractionManager.ClearAfterKeyListFinish"])
        self.assertIsNone(record["runtime_observation"]["captured_bool"])
        claims = {
            claim["id"]: claim["status"]
            for claim in load("evidence.json")["claims"]
        }
        self.assertEqual("CONFIRMED", claims["interaction-27447-native-identity"])
        self.assertEqual("UNRESOLVED", claims["interaction-27447-causal-link"])

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
