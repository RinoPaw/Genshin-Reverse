"""Synthetic native instruction and permanent source-identity gates for SceneTag."""
from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "scene_helper_cursor_71", ROOT / "scripts/audit-7.1-scene-span-cursor.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class TestSceneTagNativeSpanCursor71(unittest.TestCase):
    def test_original_client_evidence_boundary(self):
        d = json.loads(audit.REPORT.read_text(encoding="utf-8"))
        self.assertEqual(d["source"]["exeSha256"], audit.PROFILE_71.exe_sha256)
        self.assertEqual(d["source"]["callerDisassemblySha256"], audit.CALLER_SHA)
        self.assertEqual(d["source"]["cursorDisassemblySha256"], audit.HELPER_SHA)
        self.assertEqual(d["native"]["normalReturnCursorAddRva"], "0xFD53179")
        self.assertTrue(d["native"]["normalReturnCursorAdvanceMatchesSpanLength"])
        self.assertEqual(d["forwardOnlyMaxPossibleRows"], 300)
        self.assertEqual(d["originalSceneTagRows"], 1147)
        self.assertIn("VTABLE_UNRESOLVED", d["status"])
        self.assertTrue(any("not fully proved" in s for s in d["limitations"]))

    def test_synthetic_sha_and_native_instruction_gate(self):
        rva = audit.HELPER_RVA
        obj = {"exe_sha256": audit.PROFILE_71.exe_sha256,
               "image_base": hex(audit.BASE_VA), "start_rva": hex(rva),
               "instructions": [{"rva": a, "mnemonic": m, "op_str": op}
                                for a, m, op in audit.HELPER_ANCHORS]}
        raw = json.dumps(obj).encode()
        sha = hashlib.sha256(raw).hexdigest()
        verified = audit.check_native(raw, sha, rva, audit.HELPER_ANCHORS)
        self.assertEqual(verified["start_rva"], hex(rva))
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            audit.check_native(raw+b"x", sha, rva, audit.HELPER_ANCHORS)
        obj["instructions"][1]["op_str"] = "rdi, rdx"
        changed = json.dumps(obj).encode()
        with self.assertRaisesRegex(ValueError, "instruction mismatch"):
            audit.check_native(changed, hashlib.sha256(changed).hexdigest(),
                               rva, audit.HELPER_ANCHORS)

    def test_va_to_rva_is_not_double_based(self):
        self.assertEqual(0x14FD53090 - audit.BASE_VA, audit.HELPER_RVA)


if __name__ == "__main__":
    unittest.main()
