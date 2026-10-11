"""Causal-boundary tests for offline 7.1 Amber guide/input NDJSON reports."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/runtime/analyze_amber_guide_locks_71.py"
SPEC = importlib.util.spec_from_file_location("amber_guide_analysis_71", TOOL)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def line(kind, payload):
    return json.dumps({"kind": kind, "payload": payload})


def session(*events):
    return [
        line("capture_session", {"profile": "7.1.0-global/windows-x64",
                                 "pre_attach_lock_state": "unknown"}),
        line("client_native_event", {"ready": True, "hook_count": 22}),
        line("capture_config", {"verbose": True, "hook_count": 22}),
        *(line("client_native_event", {"event_index": i + 1, "elapsed_ms": i * 10, **e})
          for i, e in enumerate(events)),
    ]


class AmberGuideTraceAnalysisTests(unittest.TestCase):
    def analyze_lines(self, lines):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return MODULE.analyze(path)

    def test_rejected_guide_and_input_disable_remain_separate_evidence(self):
        report = self.analyze_lines(session(
            {"event": "stop_local_avatar"},
            {"event": "lock_inter", "reason": 1},
            {"event": "finish_curr_talk", "talk_id": 35601},
            {"event": "start_guide", "guide_name": "GuideQuestGuide"},
            {"event": "guide_start_predicate_result", "guide_name": "GuideQuestGuide",
             "accepted": False},
            {"event": "input_adapter_effective_state", "adapter_id": 1,
             "disabled": True, "disable_mask": 2},
        ))
        self.assertEqual(report["session_count"], 1)
        result = report["sessions"][0]
        self.assertTrue(result["hook_ready"])
        self.assertTrue(result["observed_finish_35601"])
        self.assertEqual(result["guide_predicate_rejections"],
                         [{"guide_name": "GuideQuestGuide", "event_index": 5}])
        self.assertEqual(result["observed_unpaired_interaction_reasons"], [1])
        self.assertTrue(result["latest_adapter_states"]["1"]["disabled"])
        self.assertEqual(result["latest_adapter_states"]["1"]["disable_mask"], 2)
        self.assertEqual(result["timeline"][0]["phase"], "before_35601_finish_callback")
        self.assertEqual(result["timeline"][2]["phase"], "at_or_after_35601_finish_callback")
        self.assertTrue(any("does not prove" in x for x in result["interpretation_limits"]))
        self.assertTrue(any("not global input state" in x for x in result["findings"]))
        self.assertFalse(any("root cause" in x.lower() for x in result["findings"]))

    def test_append_mode_multiple_sessions_must_not_merge_locks(self):
        first = session({"event": "lock_inter", "reason": 1},
                        {"event": "finish_curr_talk", "talk_id": 35601})
        second = session({"event": "finish_curr_talk", "talk_id": 35601},
                         {"event": "unlock_inter", "reason": 1})
        report = self.analyze_lines(first + second)
        self.assertEqual(report["session_count"], 2)
        self.assertEqual(report["sessions"][0]["observed_unpaired_interaction_reasons"], [1])
        self.assertEqual(report["sessions"][1]["observed_unpaired_interaction_reasons"], [])
        self.assertEqual(report["sessions"][1]["guide_predicate_rejections"], [])

    def test_lock_and_matching_unlock_do_not_report_pending_reason(self):
        report = self.analyze_lines(session(
            {"event": "lock_inter", "reason": 3},
            {"event": "unlock_inter", "reason": 3},
            {"event": "finish_curr_talk", "talk_id": 35601},
        ))
        self.assertEqual(report["sessions"][0]["observed_unpaired_interaction_reasons"], [])

    def test_missing_handoff_is_warning_not_conclusion(self):
        report = self.analyze_lines(session({"event": "start_guide",
                                             "guide_name": "GuideQuestGuidePC"}))
        result = report["sessions"][0]
        self.assertFalse(result["observed_finish_35601"])
        self.assertTrue(any("FinishCurrTalk" in x for x in result["capture_warnings"]))
        self.assertEqual(result["timeline"][0]["phase"], "unanchored")

    def test_broken_ndjson_and_missing_hooks_report_incompleteness(self):
        report = self.analyze_lines([
            line("capture_session", {"profile": "7.1.0-global/windows-x64"}),
            "{broken",
            line("frida_message", {"type": "error", "stack": "mock error"}),
        ])
        warnings = report["sessions"][0]["capture_warnings"]
        self.assertTrue(any("invalid JSON" in x for x in warnings))
        self.assertTrue(any("Frida script error" in x for x in warnings))
        self.assertTrue(any("ready event" in x for x in warnings))
        self.assertTrue(any("capture_config" in x for x in warnings))

    def test_cli_json_file_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "trace.ndjson"
            dst = Path(tmp) / "report.json"
            src.write_text("\n".join(session(
                {"event": "finish_curr_talk", "talk_id": 35601},
                {"event": "set_newbie_mask_compulsory", "compulsory": False},
            )), encoding="utf-8")
            subprocess.run(
                [sys.executable, str(TOOL), str(src), "--output", str(dst)],
                check=True, cwd=ROOT, capture_output=True, text=True,
            )
            report = json.loads(dst.read_text(encoding="utf-8"))
            self.assertEqual(report["session_count"], 1)
            self.assertFalse(report["sessions"][0]["timeline"][0].get("compulsory", True)
                             if report["sessions"][0]["timeline"][0]["event"]
                             == "set_newbie_mask_compulsory"
                             else report["sessions"][0]["timeline"][1]["compulsory"])


if __name__ == "__main__":
    unittest.main()
