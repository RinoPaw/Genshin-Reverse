"""Cheap regression tests for the source-gated original 7.1 Gadget audit.

The exact original client binary is verified only by the opt-in source run;
ordinary CI checks the documented aggregate and the fail-closed source gate.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/audit-7.1-gadget-native-rows.py"
spec = importlib.util.spec_from_file_location("audit_gadget_71", SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class TestGadgetAudit71(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(audit.REPORT.read_text(encoding="utf-8"))

    def test_source_gate_rejects_unverified_bytes_before_parser(self):
        with self.assertRaisesRegex(ValueError, "size or SHA-256"):
            audit.audit(b"not the exact 7.1 Gadget original export")
        with self.assertRaisesRegex(ValueError, "size or SHA-256"):
            audit.audit(bytes(audit.RAW_SIZE))

    def test_aggregate_full_table_partitions_are_consistent(self):
        report = self.report
        self.assertEqual(report["source"]["rawExportSha256"], audit.RAW_SHA256)
        self.assertEqual(report["source"]["payloadSha256"], audit.PAYLOAD_SHA256)
        frame = report["observedFraming"]
        self.assertEqual(frame["rowCount"], audit.ROW_COUNT)
        self.assertEqual(frame["uniqueNativeIds"], audit.ROW_COUNT)
        self.assertEqual(frame["firstNativeId"], 40000001)
        self.assertTrue(frame["lastDecodedRecordEndsAtEof"])
        self.assertTrue(frame["headerDecoded"])
        self.assertEqual(frame["headerDecodedCount"], 30599)
        self.assertEqual(frame["baseMaskDecodeAdd"], "0x5486")
        self.assertEqual(
            frame["innerDecodedBytes"] +
            frame["nativeBaseDecodedBytes"] +
            frame["headerBytes"],
            audit.PAYLOAD_SIZE)
        histogram = frame["baseOtherFieldLengthHistogram"]
        self.assertEqual(sum(histogram.values()), audit.ROW_COUNT)
        self.assertEqual(sum(int(k) * v for k, v in histogram.items()),
                         frame["nativeBaseOtherFieldBytes"])
        self.assertEqual(len(report["fieldPresenceCountByCandidateMemoryOffset"]), 22)
        base = report["inheritedNativeFields"]
        self.assertEqual(sum(base["maskCounts"].values()), audit.ROW_COUNT)
        self.assertEqual(base["maskCounts"]["0x17"], 22913)
        self.assertEqual(base["maskCounts"]["0x97"], 6113)
        self.assertEqual(base["chestMaskCounts"], {"0x17": 134, "0x97": 175})
        self.assertEqual(base["distinctStringValues"], 14)
        self.assertEqual(base["stringCount"], 6427)
        self.assertEqual(sum(base["stringOccurrences"].values()), 6427)

    def test_enum26_and_boolean_wire_missingness_are_explicit(self):
        subset = self.report["enum26CrossCheck"]
        self.assertEqual(subset["nativeTypeCandidateMemoryOffset"], "0x6C")
        self.assertEqual(subset["rowCount"], 309)
        self.assertEqual(subset["distinctNameStrings"], 148)
        self.assertEqual(
            [row["gadgetId"] for row in subset["normalChestControls"]],
            list(range(70210001, 70210007)))
        self.assertEqual(len(subset["candidateBooleanWireCoverage"]), 8)
        for stat in subset["candidateBooleanWireCoverage"].values():
            self.assertEqual(
                stat["presentTrue"] + stat["presentFalse"] +
                stat["absentOnWire"], subset["rowCount"])
        self.assertEqual(
            subset["candidateBooleanWireCoverage"]["0x78"]["nativeToken"],
            "NGDGAAEHPHB")
        self.assertEqual(
            subset["candidateBooleanWireCoverage"]["0x7C"]["nativeToken"],
            "MECPCDBEFBG")
        self.assertEqual(
            subset["candidateBooleanWireCoverage"]["0x7F"]["nativeToken"],
            "OLOLLKJCHHI")
        self.assertNotIn("dropTag", subset)
        self.assertNotIn("chestGrade", subset)


if __name__ == "__main__":
    unittest.main()
