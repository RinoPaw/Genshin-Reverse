"""Synthetic regression checks for source-pinned 7.1 Gadget reader caller probe."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/probe-7.1-gadget-reader-callers.py"
spec = importlib.util.spec_from_file_location("gadget_caller_71", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class TestGadgetReaderCallers71(unittest.TestCase):
    def test_source_gate_precedes_scan(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "fake-client.exe"
            path.write_bytes(b"not the exact client")
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                probe.run(path, Path(root) / "missing.csv")

    def test_git_blob_is_pinned_to_file_bytes(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "methods.csv"
            raw = b"test"
            path.write_bytes(raw)
            self.assertEqual(probe.git_blob(path),
                             hashlib.sha1(b"blob 4\0test").hexdigest())

    def test_method_and_pointer_candidates_stay_unverified(self):
        key = "0x10278E50"
        call = {"instruction_rva": "0x1027A000", "target_rva": key,
                "caller_methods": [{"type_name": "OpaqueLoader", "rva": "0x10279FFF"}]}
        direct = {"matches": {key: [call]}}
        pointers = {"holders": [
            {"section": ".rdata", "holder_rva": "0x100",
             "target_rva": key, "code_xrefs": []}
        ], "holder_count": 1, "holders_with_code_xrefs": 0}
        result = probe.summarize(direct, pointers)
        self.assertEqual(result["directCallCandidateCount"], 1)
        self.assertEqual(result["methodRowsAttributedToDirectCandidates"], 1)
        self.assertEqual(result["alignedMethodPointerCandidateCount"], 1)
        self.assertEqual(result["methodPointersWithSimpleRipXrefs"], 0)
        self.assertIn("LOADER_UNVERIFIED", result["status"])
        self.assertNotIn("chestGrade", result)
        self.assertNotIn("dropTag", result)

    def test_empty_xrefs_are_valid_negative_scope(self):
        result = probe.summarize(
            {"matches": {"0x10278E50": []}},
            {"holders": [], "holder_count": 0, "holders_with_code_xrefs": 0})
        self.assertEqual(result["directCallCandidateCount"], 0)
        self.assertEqual(result["alignedMethodPointerCandidateCount"], 0)
        self.assertIn("Indirect calls", result["limits"][4])


if __name__ == "__main__":
    unittest.main()
