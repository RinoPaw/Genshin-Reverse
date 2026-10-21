"""Regression for SHA-256-pinned original SceneTag/SceneExcel byte motif evidence."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "native_scene_motifs_71", ROOT / "scripts/audit-7.1-scene-native-byte-motifs.py")
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class TestOriginalSceneMotifs71(unittest.TestCase):
    def test_overlapping_motifs_and_disjoint_windows(self):
        self.assertEqual(PROBE.find_offsets(b"aaaa", b"aa"), [0,1,2])
        self.assertEqual(PROBE.find_offsets(b"abcdabc", b"abc"), [0,4])
        self.assertEqual(PROBE.find_offsets(b"ababa", b"xx"), [])
        with self.assertRaisesRegex(ValueError, "empty"):
            PROBE.find_offsets(b"abc", b"")

    def test_source_pinned_snapshot_matches_both_native_row_counts(self):
        snapshot = json.loads(PROBE.OUTPUT.read_text(encoding="utf-8"))
        self.assertIn("ROW_DELIMITERS_UNVERIFIED", snapshot["status"])
        self.assertEqual(set(snapshot["tables"]), set(PROBE.MOTIFS))
        tag = snapshot["tables"]["SceneTagConfigData"]
        excel = snapshot["tables"]["SceneExcelConfigData"]
        self.assertEqual((tag["nativeLoaderRowCount"], tag["motifOccurrences"]),
                         (1147, 1147))
        self.assertEqual((excel["nativeLoaderRowCount"], excel["motifOccurrences"]),
                         (2377, 2377))
        self.assertEqual(tag["motifBytesHex"], "690d4f")
        self.assertEqual(excel["motifBytesHex"], "00000000")
        # Distinct variable-length motifs are observations only. Guard
        # a small offset window and spacing to catch byte-offset drift.
        self.assertEqual(tag["firstOffsets"][:4], [12, 56, 109, 153])
        self.assertEqual(tag["lastOffsets"][-3:], [38849, 38888, 38924])
        self.assertEqual((tag["neighborDistanceMin"],
                          tag["neighborDistanceMedian"],
                          tag["neighborDistanceMax"]), (24, 33, 57))
        self.assertEqual(excel["firstOffsets"][:4], [8, 48, 88, 129])
        self.assertEqual(excel["lastOffsets"][-3:], [273128, 273206, 273279])
        self.assertEqual((excel["neighborDistanceMin"],
                          excel["neighborDistanceMedian"],
                          excel["neighborDistanceMax"]), (37, 121, 189))

        self.assertEqual(tag["allOffsetsSha256"],
                         "960a89ca333aaf76ed49e0feb6eb5368a63797df85de8282752b72c4572656b4")
        self.assertEqual(excel["allOffsetsSha256"],
                         "89b7209f022dd3f0aa03bee4a021eb2088d59c47bfde3aff5eb6c0107c8aaf1d")
        for item in snapshot["tables"].values():
            self.assertFalse(item["nativeFieldOwnerIdentified"])
            self.assertFalse(item["motifProvenRowDelimiter"])
            self.assertLess(item["neighborDistanceMin"], item["neighborDistanceMax"])
            self.assertEqual(len(item["firstOffsets"]), 12)
            self.assertEqual(len(item["lastOffsets"]), 12)
            self.assertEqual(len(item["originalRawExportSha256"]), 64)
        self.assertTrue(any("does not" in s or "no proven" in s
                            for s in snapshot["limitations"]))

    def test_forged_original_bytes_rejected_before_counting(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            PROBE.inspect({
                "SceneTagConfigData": b"fake",
                "SceneExcelConfigData": b"fake",
            })


if __name__ == "__main__":
    unittest.main()
