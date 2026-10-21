"""Exact 7.1 scene row class static-pointer RIP evidence tests."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/probe-7.1-scene-row-class-xrefs.py"
spec = importlib.util.spec_from_file_location("scene_row_class_71", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def fake_reference(name, **kwargs):
    entry = probe.ANCHORS[name]
    return {
        "instruction_rva": f"0x{entry['rowClassLoadRva']:X}",
        "instruction_hex": entry["rowClassLoadInstructionBytes"],
        "access": "read",
        "caller_methods": [{
            "method_index": "696653" if name == "SceneTag" else "279989",
            "type_name": "EJCNENCJADF" if name == "SceneTag" else "HPNMCGDJOJL",
            "method_name": "GMENPOPMKAA",
            "rva": f"0x{entry['loaderRva']:X}",
        }],
        **kwargs,
    }


class TestSceneRowClassXrefs71(unittest.TestCase):
    def test_exact_native_loader_rip_class_global_ownership(self):
        self.assertEqual(probe.class_pointer_rva(probe.ANCHORS["SceneTag"]), 0x57EA618)
        self.assertEqual(probe.class_pointer_rva(probe.ANCHORS["SceneExcel"]), 0x58113D0)
        self.assertNotEqual(probe.class_pointer_rva(probe.ANCHORS["SceneTag"]),
                            probe.class_pointer_rva(probe.ANCHORS["SceneExcel"]))
        self.assertEqual(probe.ANCHORS["SceneTag"]["rowClassLoadRva"], 0x14015504)
        self.assertEqual(probe.ANCHORS["SceneExcel"]["rowClassLoadRva"], 0xA6C70A4)

    def test_synthetic_source_xref_positive_control_and_method_attribution(self):
        data = {"matches": {
            f"0x{probe.class_pointer_rva(entry):X}": [fake_reference(name)]
            for name, entry in probe.ANCHORS.items()
        }}
        report = probe.summarize(data)
        self.assertEqual(report["tables"]["SceneTag"]["referenceCount"], 1)
        self.assertEqual(report["tables"]["SceneExcel"]["referenceCount"], 1)
        self.assertEqual(report["tables"]["SceneTag"]["referenceSites"][0]
                         ["metadataOwners"][0]["methodIndex"], "696653")
        self.assertIn("UNRESOLVED", report["status"])
        self.assertNotIn("nativeRowReaderRva", report)

    def test_wrong_global_or_broad_xref_set_fails_closed(self):
        data = {"matches": {
            f"0x{probe.class_pointer_rva(entry):X}": [fake_reference(name)]
            for name, entry in probe.ANCHORS.items()
        }}
        data["matches"]["0x57EA618"][0]["instruction_hex"] = "00"
        with self.assertRaisesRegex(ValueError, "positive control missing"):
            probe.summarize(data)
        data["matches"]["0x57EA618"][0]["instruction_hex"] = (
            probe.ANCHORS["SceneTag"]["rowClassLoadInstructionBytes"])
        data["matches"]["0x57EA618"] *= 1025
        with self.assertRaisesRegex(ValueError, "unexpectedly broad"):
            probe.summarize(data)

    def test_wrong_executable_hash_rejected_first(self):
        with (patch.object(probe, "require_sha256", side_effect=ValueError("wrong sha")),
              patch.object(probe, "scan_rip_xrefs") as scan):
            with self.assertRaisesRegex(ValueError, "wrong sha"):
                probe.run(Path("wrong.exe"), Path("methods.csv"))
        scan.assert_not_called()


if __name__ == "__main__":
    unittest.main()
