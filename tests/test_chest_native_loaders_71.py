"""Pinned native count loader instruction verification, synthetic only."""
from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/audit-7.1-chest-native-loaders.py"
spec = importlib.util.spec_from_file_location("chest_native_disasm_71", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def fixture():
    ret = {}
    for key, t in mod.TARGETS.items():
        rows = []
        if "movRva" in t:
            rows.append({"rva": f"0x{t['movRva']:X}", "mnemonic": "mov",
                         "op_str": f"edi, 0x{t['immediate']:x}", "bytes": "bf"})
            rows.append({"rva": f"0x{t['xorRva']:X}", "mnemonic": "xor",
                         "op_str": "edi, dword ptr [rax + rcx + 0x20]",
                         "bytes": "337c0820"})
            rows.append({"rva": f"0x{t['xorRva']+4:X}", "mnemonic": "call",
                         "op_str": "qword ptr [rax + 0xf0]",
                         "bytes": "ff90f0000000"})
        else:
            rows.append({"rva": f"0x{t['entryRva']:X}", "mnemonic": "ret",
                         "op_str": "", "bytes": "c3"})
        ret[key] = {"exe_sha256": mod.PROFILE_71.exe_sha256,
                    "start_rva": f"0x{t['entryRva']:X}",
                    "size": t["size"], "instructions": rows}
    return ret


class NativeChestLoaderDisasmTests(unittest.TestCase):
    def test_exact_anchors_and_bounded_virtual_leads(self):
        report = mod.verify(fixture())
        self.assertEqual(report["regions"]["audioLoader"]
                         ["fixedCountHypothesisFromHeaderAndNativeXor"], 56)
        self.assertEqual(report["regions"]["investigationLoader"]
                         ["fixedCountHypothesisFromHeaderAndNativeXor"], 252)
        self.assertEqual(len(report["regions"]["audioLoader"]
                             ["observedVirtualF0CallsInWindow"]), 1)
        self.assertFalse(report["regions"]["audioRowReaderCandidate"]
                         ["nativeCountInstructionAnchorsVerified"])

    def test_unmatched_original_source_fails_closed(self):
        data = fixture()
        data["audioLoader"]["exe_sha256"] = "different"
        with self.assertRaisesRegex(ValueError, "exact RVA range mismatch"):
            mod.verify(data)
        data = fixture()
        data["audioLoader"]["instructions"][1]["op_str"] = "edi, dword ptr [r8]"
        with self.assertRaisesRegex(ValueError, "XOR anchor mismatch"):
            mod.verify(data)
        data = fixture()
        data["investigationLoader"]["instructions"][0]["rva"] = "0x1"
        with self.assertRaisesRegex(ValueError, "MOV anchor mismatch"):
            mod.verify(data)

    def test_duplicate_addresses_not_accepted(self):
        data = fixture()
        data["audioLoader"]["instructions"].append(
            copy.deepcopy(data["audioLoader"]["instructions"][0]))
        with self.assertRaisesRegex(ValueError, "repeated RVA"):
            mod.verify(data)


if __name__ == "__main__":
    unittest.main()
