from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PY_CAPTURE = ROOT / "tools" / "runtime" / "capture_game_packets_71.py"
JS_CAPTURE = ROOT / "tools" / "runtime" / "capture_game_packets_71.js"


class RuntimeCaptureContractTests(unittest.TestCase):
    def test_python_launcher_uses_native_profile_and_explicit_watch_cmds(self) -> None:
        text = PY_CAPTURE.read_text(encoding="utf-8")
        self.assertIn("from genshinre.nativeprofile import PROFILE_71", text)
        self.assertIn('"--watch-cmd"', text)
        self.assertNotIn("EXPECTED_EXE_SHA256", text)
        self.assertNotIn("UnlockTransPoint", text)

    def test_frida_probe_has_no_packet_specific_default_watch_set(self) -> None:
        text = JS_CAPTURE.read_text(encoding="utf-8")
        self.assertIn("let WATCHED = new Set();", text)
        self.assertIn("configure(watchedCmdIds)", text)
        for cmd_id in (9369, 36641, 20290, 25567):
            with self.subTest(cmd_id=cmd_id):
                self.assertNotIn(str(cmd_id), text)


if __name__ == "__main__":
    unittest.main()
