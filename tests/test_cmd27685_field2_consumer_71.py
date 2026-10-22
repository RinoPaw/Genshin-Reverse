"""Pinned original client direct-target and provenance gates for Cmd27685."""
from importlib import util
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = util.spec_from_file_location(
    "original_cmd27685_callee",
    ROOT / "scripts/probe-7.1-cmd27685-field2-consumer.py")
m = util.module_from_spec(spec)
spec.loader.exec_module(m)


class NativeCallsite(unittest.TestCase):
    def test_original_direct_target(self):
        self.assertEqual(m.decode_direct_call(m.CALLSITE_RVA, m.ORIGINAL_OPCODE),
                         m.TARGET_RVA)
        self.assertEqual(m.TARGET_RVA, 0x184EE960)
        self.assertEqual(m.PRE_CALL_INSTRUCTIONS[0],
                         (0xFCDF6B2, "8b9098000000"))

    def test_mismatched_call_rejected(self):
        with self.assertRaisesRegex(ValueError, "expected five-byte"):
            m.decode_direct_call(m.CALLSITE_RVA, b"\x90"*5)
        with self.assertRaisesRegex(ValueError, "expected five-byte"):
            m.decode_direct_call(m.CALLSITE_RVA, b"\xe8\x00")


if __name__ == "__main__":
    unittest.main()
