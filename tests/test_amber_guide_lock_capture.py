"""Static guardrails for the read-only 7.1 native Amber guide probe.

These tests do not execute Frida or make claims about in-game behavior.
"""

from __future__ import annotations

import ast
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "tools/runtime/capture_amber_guide_locks_71.py"
SCRIPT = ROOT / "tools/runtime/capture_amber_guide_locks_71.js"


class AmberGuideLockCaptureStaticTests(unittest.TestCase):
    def test_frida_script_js_syntax_when_node_is_available(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js not available; static source checks still run")
        subprocess.run([node, "--check", str(SCRIPT)], check=True, capture_output=True, text=True)

    def test_launcher_syntax_and_exact_binary_guard(self) -> None:
        source = LAUNCHER.read_text(encoding="utf-8")
        ast.parse(source, filename=str(LAUNCHER))
        self.assertIn("require_profile_exe(args.exe, PROFILE_71)", source)
        self.assertLess(source.index("require_profile_exe(args.exe, PROFILE_71)"),
                        source.index("frida.attach(args.process)"))
        self.assertIn('"pre_attach_lock_state": "unknown"', source)
        self.assertIn('"capture_start_requirement": "before quest 35601 starts', source)
        self.assertIn('Attach BEFORE quest 35601 starts', source)

    def test_probe_has_only_read_only_native_hooks(self) -> None:
        js = SCRIPT.read_text(encoding="utf-8")
        for rva in (
            "0xA5E18C0", "0xFE57430", "0xFE508D0", "0xFE552F0",
            "0xFE284A0", "0xFE28170", "0x9E2C4B0", "0x1163D740",
            "0xA5CE790", "0x89FB050", "0x758D8C0", "0x758DBD0",
        ):
            self.assertIn(rva, js)
        self.assertEqual(22, js.count("{ name: '"))
        self.assertIn("Interceptor.attach(", js)
        for forbidden in ("Memory.write", "writePointer(", "writeU8(",
                          "writeS32(", "NativeFunction("):
            self.assertNotIn(forbidden, js)

    def test_pre_mask_guide_rejection_is_logged_without_overriding_result(self) -> None:
        js = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("name: 'guide_start_predicate'", js)
        self.assertIn("name: 'guide_start_dispatch'", js)
        self.assertIn("event: 'guide_start_predicate_result'", js)
        self.assertIn("accepted: result === null ? null : (result & 0xff) !== 0", js)
        self.assertIn("onLeave(retval)", js)
        self.assertNotIn("retval.replace(", js)

    def test_avatar_stop_and_player_input_hooks_use_exact_71_metadata_rvas(self) -> None:
        js = SCRIPT.read_text(encoding="utf-8")
        anchors = {
            "stop_local_avatar": "0xFE296E0",
            "base_actor_enable_player_input": "0x13AF5060",
            "actor_utils_enable_player_input": "0x13A9BAE0",
            "actor_utils_enable_input_by_quest": "0x13A9B510",
            "actor_utils_set_ui_lock_state": "0x13AA0120",
            "actor_utils_set_quest_dialog_enable": "0x13ABEED0",
        }
        for name, rva in anchors.items():
            self.assertIn(f"name: '{name}', rva: {rva}", js)
        self.assertIn("event.raw_arg0 = safeInt(args[0]);", js)
        self.assertIn("event.raw_arg1 = safeInt(args[1]);", js)
        self.assertIn("event.raw_arg2 = safeInt(args[2]);", js)
        self.assertIn("base_actor_enable_player_input: 1", js)
        self.assertIn("actor_utils_enable_player_input: 0", js)
        self.assertIn("actor_utils_set_ui_lock_state: 0", js)
        self.assertIn("actor_utils_set_quest_dialog_enable: 0", js)
        self.assertIn("event.ui_locked = value;", js)
        self.assertIn("event.enabled = value;", js)
        self.assertIn("name: 'input_adapter_update_input_disable', rva: 0xAC528D0", js)
        self.assertIn("name: 'input_adapter_update_mask', rva: 0xAC529B0", js)
        self.assertIn("pointer.add(0x18).readU8()", js)
        self.assertIn("pointer.add(0x1C).readU32()", js)
        self.assertIn("event: 'input_adapter_disable_request'", js)
        self.assertIn("event: 'input_adapter_effective_state'", js)
        self.assertNotIn("Memory.write", js)
        self.assertNotIn("retval.replace(", js)

    def test_probe_does_not_capture_packet_payloads(self) -> None:
        js = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("frame_hex", js)
        self.assertNotIn("head_hex", js)
        self.assertIn("guide_name", js)
        self.assertIn("lock_inter", js)
        self.assertIn("unlock_inter", js)


if __name__ == "__main__":
    unittest.main()
