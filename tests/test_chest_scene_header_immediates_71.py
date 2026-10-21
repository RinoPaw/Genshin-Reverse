"""Scope tests for exact 7.1 SceneExcel/SceneTag count-header leads."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "scripts/probe-7.1-scene-header-immediates.py"
spec = importlib.util.spec_from_file_location("scene_header_immediate_71", path)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class TestOriginalSceneCountHeaderLeads71(unittest.TestCase):
    def test_source_head_provisional_add_sub_xor(self):
        tag = bytes.fromhex("48996af1")
        scene = bytes.fromhex("8dea4d47")
        a = probe.candidates(tag, 1147)
        b = probe.candidates(scene, 2377)
        self.assertEqual(a["addModulo32"], 0x0E956B33)
        self.assertEqual(b["addModulo32"], 0xB8B21EBC)
        self.assertEqual((int.from_bytes(tag,"little") + a["addModulo32"])
                         & probe.U32, 1147)
        self.assertEqual((int.from_bytes(scene,"little") + b["addModulo32"])
                         & probe.U32, 2377)
        self.assertEqual(int.from_bytes(tag,"little") ^ a["xor32"], 1147)
        self.assertEqual((int.from_bytes(scene,"little") - b["subModulo32"])
                         & probe.U32, 2377)
        self.assertNotEqual(a["xor32"], a["addModulo32"])

    def test_invalid_input_and_absent_native_field_claim(self):
        for raw, count in ((b"", 1147), (bytes(4), 0),
                           (bytes(4), 100_000)):
            with self.assertRaisesRegex(ValueError, "invalid bounded"):
                probe.candidates(raw, count)
        self.assertEqual(set(probe.SOURCES),
                         {"SceneExcelConfigData", "SceneTagConfigData"})
        self.assertEqual(probe.SOURCES["SceneTagConfigData"]["historicalRows"], 1147)
        self.assertEqual(probe.SOURCES["SceneExcelConfigData"]["historicalRows"], 2377)

    def test_source_hash_check_fails_before_pe_scan(self):
        with patch.object(probe, "require_sha256") as src:
            with self.assertRaisesRegex(ValueError, "SceneTagConfigData SHA-256"):
                probe.inspect(Path("fake.exe"), Path("m.csv"), {
                    "SceneTagConfigData": b"wrong",
                    "SceneExcelConfigData": b"wrong",
                })
        src.assert_called_once()


if __name__ == "__main__":
    unittest.main()
