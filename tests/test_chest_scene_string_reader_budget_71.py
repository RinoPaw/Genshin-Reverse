"""Regression for exact-source 7.1 SceneTag 696558 conditional reader bound."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/audit-7.1-scene-string-reader-budget.py"
REPORT = (ROOT / "versions/7.1.0-global/analyses/progression/economy"
          / "7.1-chest-scene-string-reader-budget.json")
spec = importlib.util.spec_from_file_location("scene_string_budget_71", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class TestSceneTagReaderBudget71(unittest.TestCase):
    def test_pinned_source_scoped_conditional_rejection(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        source = report["source"]
        self.assertEqual(source["originalExecutableSha256"], probe.PROFILE_71.exe_sha256)
        self.assertEqual(source["rawSha256"], probe.SOURCES["SceneTagConfigData"]["raw_sha"])
        self.assertEqual(source["candidateDisassemblySha256"], probe.DISASM_SHA256)
        self.assertEqual(source["nativeAnchorsMatched"], len(probe.ANCHORS))
        self.assertEqual(source["candidateMethodIndex"], 696558)
        self.assertEqual(report["firstRow"]["decodedMaskU16"], "0xDDFD")
        self.assertEqual(report["firstRow"]["mandatoryLengthFromBit0x20"], 35703)
        self.assertEqual(report["firstRow"]["minimumCursorAfterNativeReads"], 35723)
        bound = report["forwardOnlyRelaxedBound"]
        self.assertEqual((bound["maxPossibleRows"], bound["originalRowCount"]),
                         (300, 1147))
        self.assertFalse(bound["candidateMeetsOriginalRowCount"])
        self.assertTrue(any("conditional" in s for s in report["limitations"]))
        self.assertIn("VTABLE_UNRESOLVED", report["status"])

    def test_synthetic_mask_and_len_reads_are_mandatory(self):
        # Mask 0x0000 -> 0x6610 raw; only native u16 is required.
        minimal = struct.pack("<H", 0x6610) * 6
        self.assertEqual(probe.relaxed_max_rows(b"\0" * 4 + minimal)[
            "maxRowsStartingAtOffset"], 6)
        # Mask 0x0020 -> 0x6630 raw: length plus opaque bytes are required.
        prefix = (b"\0" * 4 + struct.pack("<HH", 0x6630,
                 (10 - 0x75D6) & 0xFFFF) + b"\xAA" * 10)
        self.assertEqual(probe.necessary_fields(prefix, 4)["necessaryEnd"], 18)
        self.assertEqual(probe.relaxed_max_rows(prefix)["maxRowsStartingAtOffset"], 1)
        self.assertIsNone(probe.necessary_fields(prefix[:-1], 4))

    def test_unknown_helper_can_skip_arbitrary_forward_bytes(self):
        # The optional 0x01 helper is permitted to skip any bytes; this
        # deliberately overestimates the number of executable rows.
        prefix = b"\0" * 4 + struct.pack("<H", 0x6611)
        payload = prefix + b"\xAB" * 3 + struct.pack("<H", 0x6610) * 3
        self.assertEqual(probe.relaxed_max_rows(payload)["maxRowsStartingAtOffset"], 4)
        with self.assertRaises(ValueError):
            probe.relaxed_max_rows(payload, -1)

    def test_native_source_hash_is_mandatory(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            probe.audit(b"not original", b"wrong disassembly")


if __name__ == "__main__":
    unittest.main()
