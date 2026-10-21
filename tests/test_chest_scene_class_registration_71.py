"""Synthetic checks for source-pinned Global 7.1 row-class static registration scan."""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "scripts/probe-7.1-scene-class-pointer-registration.py"
spec = importlib.util.spec_from_file_location("scene_static_registration_71", path)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class TestSceneClassPointerRegistration71(unittest.TestCase):
    def test_exact_native_slots_and_dispatch_sources(self):
        self.assertEqual(probe.SLOTS["SceneTag"]["rowClassRva"], 0x57EA618)
        self.assertEqual(probe.SLOTS["SceneExcel"]["rowClassRva"], 0x58113D0)
        self.assertEqual(probe.SLOTS["SceneTag"]["nativeLoadInstructionRva"],
                         0x14015504)
        self.assertEqual(probe.SLOTS["SceneExcel"]["nativeLoadInstructionRva"],
                         0xA6C70A4)
        self.assertNotEqual(probe.SLOTS["SceneTag"]["rowClassRva"],
                            probe.SLOTS["SceneExcel"]["rowClassRva"])

    def test_synthetic_absolute_va_and_rva_are_kept_separate(self):
        base = 0x140000000
        section_rva = 0x2000
        data = bytearray(64)
        data[8:16] = (base + 0x57EA618).to_bytes(8, "little")
        data[16:24] = (base + 0x58113D0).to_bytes(8, "little")
        data[32:36] = (0x57EA618).to_bytes(4, "little")
        class FakePE:
            image_base = base
            sections = [SimpleNamespace(name=".rdata", virtual_address=section_rva,
                                        raw_size=len(data), characteristics=0)]
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read_rva(self, rva, size):
                offset = rva-section_rva
                return bytes(data[offset:offset+size]) if offset >= 0 else b""

        with patch.object(probe, "require_sha256"), patch.object(
                probe, "PEImage", return_value=FakePE()):
            result = probe.scan(Path("/unused/example.exe"))
        tag = result["tables"]["SceneTag"]
        excel = result["tables"]["SceneExcel"]
        self.assertEqual(tag["fullVaQwordHolders"][0]["rva"], "0x2008")
        self.assertEqual(excel["fullVaQwordHolders"][0]["rva"], "0x2010")
        self.assertIn("0x2020", [x["rva"] for x in tag["rvaDwordCandidates"]])
        self.assertIn("VTABLE_TARGET_UNRESOLVED", result["status"])
        self.assertTrue(any("Zero direct holders" in line for line in result["limitations"]))

    def test_original_pe_required_before_scan(self):
        with patch.object(probe, "require_sha256", side_effect=ValueError("SHA-256 mismatch")):
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                probe.scan(Path("/unused/exe"))


if __name__ == "__main__":
    unittest.main()
