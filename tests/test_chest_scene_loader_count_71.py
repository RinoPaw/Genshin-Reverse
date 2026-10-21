"""Synthetic source-gate and 7.1 Gadget-native table-loader pattern tests."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "scene_loader_count_71", ROOT / "scripts/probe-7.1-scene-loader-counts.py")
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


def mov_add(reg: int, constant: int) -> bytes:
    return bytes([0xB8 + reg]) + struct.pack("<I", constant) + (
        bytes([0x03, 0x44 + reg*8, 0x08, 0x20]))


class TestNativeSceneLoaderCounts71(unittest.TestCase):
    def test_native_gadget_loader_exact_bytes_positive_control(self):
        native = bytes.fromhex("bf5eabf523037c0820")
        self.assertEqual(native, mov_add(7, 0x23F5AB5E))
        rows = tool.candidates_in_section(b"\x90\x90" + native, 0x968F6D7)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["candidateMovRva"], "0x968F6D9")
        self.assertEqual(rows[0]["candidateAddRva"], "0x968F6DE")
        self.assertEqual(rows[0]["addImmediate"], "0x23F5AB5E")
        self.assertEqual(rows[0]["register"], 7)

    def test_other_matching_registers_and_rejects_near_misses(self):
        data = (mov_add(0, 0x12345678) +
                b"\x90" +
                mov_add(3, 0x23456789) +
                b"\x90" +
                b"\xbf\x01\x02\x03\x04\x03\x44\x08\x20" +
                b"\x90" +
                b"\xb8\x01\x02\x03\x04\x03\x44\x00\x20")
        rows = tool.candidates_in_section(data, 0x1000)
        self.assertEqual(len(rows), 2)
        self.assertEqual([r["register"] for r in rows], [0, 3])
        self.assertEqual([r["addImmediate"] for r in rows],
                         ["0x12345678", "0x23456789"])

    def test_bad_unpinned_exports_fail_before_pe_scan(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            with patch.object(tool, "require_sha256"):
                with self.assertRaises(FileNotFoundError):
                    tool.audit(Path("dummy.exe"), Path("methods.csv"),
                               Path(td))
        self.assertEqual(tool.INPUTS["Gadget"][2], 30599)
        self.assertEqual(tool.INPUTS["SceneTag"][2], 1147)
        self.assertEqual(tool.INPUTS["SceneExcel"][2], 2377)
        self.assertEqual(
            (1147 - 0xF16A9948) & 0xFFFFFFFF, 0x0E956B33)
        self.assertEqual(
            (2377 - 0x474DEA8D) & 0xFFFFFFFF, 0xB8B21EBC)


if __name__ == "__main__":
    unittest.main()
