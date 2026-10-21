"""Source identity and exact 7.1 Scene allocation-pointer xref regression."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "scene_row_global_probe_71", ROOT / "scripts/probe-7.1-scene-row-class-globals.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def samples():
    results = {}
    for owner, source in tool.SITES.items():
        for _, (site, target) in source.items():
            results[f"0x{target:X}"] = [{
                "instruction_rva": f"0x{site:X}", "instruction_hex": "488b0d00000000",
                "mnemonic": "mov", "access": "read",
                "caller_methods": [{
                    "method_index": "696653" if owner == "SceneTagConfigData" else "279989",
                    "type_name": "EJCNENCJADF" if owner == "SceneTagConfigData" else "HPNMCGDJOJL",
                    "method_name": "GMENPOPMKAA", "rva": "0x14015460",
                }],
            }]
    return {"matches": results}


class FakePE:
    def __enter__(self):
        return self
    def __exit__(self, *_args):
        return False
    def read_rva(self, _rva, _size):
        return b""


class TestNativeSceneRowClassGlobals71(unittest.TestCase):
    def test_exact_original_loader_mov_targets(self):
        self.assertEqual(0x140154B6 + 7 - 0xE82AEAD, 0x57EA610)
        self.assertEqual(0x14015504 + 7 - 0xE82AEF3, 0x57EA618)
        self.assertEqual(0xA6C7056 + 7 - 0x4EB5C95, 0x58113C8)
        self.assertEqual(0xA6C70A4 + 7 - 0x4EB5CDB, 0x58113D0)
        self.assertEqual(len({rva for v in tool.SITES.values()
                              for _, rva in v.values()}), 4)

    def test_exact_positive_crossrefs_are_separate_from_runtime_type_identity(self):
        with (patch.object(tool, "require_sha256"),
              patch.object(tool, "scan_rip_xrefs", return_value=samples()) as scan,
              patch.object(tool, "PEImage", return_value=FakePE())):
            out = tool.investigate(Path("/fake/original.exe"), Path("/fake/methods.csv"))
        self.assertEqual(len(scan.call_args.args[1]), 4)
        self.assertIn("VIRTUAL_TARGET_UNKNOWN", out["status"])
        self.assertEqual(out["exeSha256"], tool.PROFILE_71.exe_sha256)
        for slots in out["originalNativeLoaderClassSlots"].values():
            self.assertNotEqual(slots["rowAllocationTypeSlot"]["sharedClassPointerGlobalRva"],
                                slots["mapAllocationTypeSlot"]["sharedClassPointerGlobalRva"])
            self.assertEqual(slots["rowAllocationTypeSlot"]["totalMovLeaRIPCrossReferences"], 1)
            self.assertEqual(slots["rowAllocationTypeSlot"]["fileBackedBytesAtGlobalHex"], "")
        self.assertTrue(any("do not identify managed class" in x for x in out["limits"]))

    def test_missing_native_anchor_rejected(self):
        bad = samples()
        bad["matches"]["0x57EA618"] = []
        with (patch.object(tool, "require_sha256"),
              patch.object(tool, "scan_rip_xrefs", return_value=bad),
              patch.object(tool, "PEImage", return_value=FakePE())):
            with self.assertRaisesRegex(ValueError, "loader anchor missing"):
                tool.investigate(Path("/fake.exe"), Path("/methods.csv"))


if __name__ == "__main__":
    unittest.main()
