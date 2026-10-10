"""Static guardrails for the read-only 7.1 native Amber guide probe.

These tests do not execute Frida or make claims about in-game behavior.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "tools/runtime/capture_amber_guide_locks_71.py"
SCRIPT = ROOT / "tools/runtime/capture_amber_guide_locks_71.js"


class AmberGuideLockCaptureStaticTests(unittest.TestCase):
    def test_launcher_syntax_and_exact_binary_guard(self) -> None:
        source = LAUNCHER.read_text(encoding="utf-8")
        ast.parse(source, filename=str(LAUNCHER))
        self.assertIn("require_profile_exe(args.exe, PROFILE_71)", source)
        self.assertLess(source.index("require_profile_exe(args.exe, PROFILE_71)"),
                        source.index("frida.attach(args.process)"))
        self.assertIn('"pre_attach_lock_state": "unknown"', source)

    def test_probe_has_only_read_only_native_hooks(self) -> None:
        js = SCRIPT.read_text(encoding="utf-8")
        for rva in (
            "0xA5E18C0", "0xFE57430", "0xFE508D0", "0xFE552F0",
            "0xFE284A0", "0xFE28170", "0x9E2C4B0", "0x1163D740",
            "0xA5CE790", "0x89FB050", "0x758D8C0", "0x758DBD0",
        ):
            self.assertIn(rva, js)
        self.assertEqual(14, js.count("{ name: '"))
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

    def test_probe_does_not_capture_packet_payloads(self) -> None:
        js = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("frame_hex", js)
        self.assertNotIn("head_hex", js)
        self.assertIn("guide_name", js)
        self.assertIn("lock_inter", js)
        self.assertIn("unlock_inter", js)


if __name__ == "__main__":
    unittest.main()
