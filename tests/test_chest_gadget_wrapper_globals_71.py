"""Synthetic regression for bounded Global 7.1 Gadget RIP-global xref report."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/probe-7.1-gadget-wrapper-globals.py"
spec = importlib.util.spec_from_file_location("wrapper_global_probe_71", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def hit(rva: int, access: str) -> dict:
    return {
        "instruction_rva": f"0x{rva:X}",
        "access": access, "mnemonic": "mov",
        "instruction_hex": "488b05e7ffffff",
    }


class TestGadgetWrapperGlobals71(unittest.TestCase):
    def test_exact_static_global_rvas_derived_independently(self):
        # RIP displacements and instruction lengths are from the pinned
        # native writer/getter (0xBB16020 / 0xBB15F50).
        self.assertEqual(0xBB16026 + 7 - 0x6392E45, 0x57831E8)
        self.assertEqual(0xBB15F56 + 7 - 0x6392D75, 0x57831E8)
        self.assertEqual(0xBB160A3 + 6 - 0x638AFA9, 0x578B100)
        self.assertEqual(0xBB15F6D + 6 - 0x638AE73, 0x578B100)
        self.assertEqual(probe.GLOBALS,
                         {"staticOwnerPointer": 0x57831E8,
                          "xorWord": 0x578B100})

    def test_hex_rva_method_attribution_and_bounded_candidates(self):
        ptr_rows = [hit(0x100000 + k * 7, "read") for k in range(200)]
        ptr_rows += [hit(0xBB16026, "read"), hit(0xBB15F56, "read"),
                     hit(0x1500000, "write")]
        xor_rows = [hit(0xBB160A3, "read"), hit(0xBB15F6D, "read"),
                    hit(0x2000000, "write")]
        fake_result = {"matches": {
            "0x57831E8": ptr_rows, "0x578B100": xor_rows}}
        class FakePE:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read_rva(self, rva, size):
                return bytes([0x17]) * size

        def metadata(sites, methods, **kwargs):
            self.assertTrue(all(isinstance(site, int) for site in sites))
            return {site: [{"method_index": "197827", "method_name": "GMENPOPMKAA",
                            "type_name": "AACCGEFDDMD", "rva": "0x968F690"}]
                    for site in sites}
        with (patch.object(probe, "PEImage", return_value=FakePE()),
              patch.object(probe, "scan_rip_xrefs", return_value=fake_result),
              patch.object(probe, "require_sha256"),
              patch.object(probe, "attach_caller_methods", side_effect=metadata)):
            report = probe.audit(Path("/unused/official.exe"),
                                 Path("/unused/methods.csv"))
        self.assertEqual(report["totalXrefsByGlobal"],
                         {"staticOwnerPointer": 203, "xorWord": 3})
        self.assertEqual(report["totalCandidateWritesByGlobal"],
                         {"staticOwnerPointer": 1, "xorWord": 1})
        self.assertEqual(report["globallyReferencedLocations"]
                         ["staticOwnerPointer"]["fileSectionValueHex"],
                         "17" * 8)
        ptr_candidates = report["boundedXrefSamples"]["staticOwnerPointer"]
        self.assertLessEqual(len(ptr_candidates), 15)
        self.assertIn("0xBB16026", [x["instructionRva"] for x in ptr_candidates])
        self.assertIn("0xBB15F56", [x["instructionRva"] for x in ptr_candidates])
        self.assertEqual(len(report["boundedXrefSamples"]["xorWord"]), 3)
        self.assertIn("DYNAMIC_TABLE_UNRESOLVED", report["status"])


if __name__ == "__main__":
    unittest.main()
