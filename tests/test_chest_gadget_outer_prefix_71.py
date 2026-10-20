"""Regression checks for the 7.1 source-gated outer-prefix observations.

The real client export is never embedded in CI. Exact-byte reproduction is
handled by the read-only audit with the SHA-256 checks before parsing.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest

from genshinre.gadgetbin import GadgetRow, GadgetTableScan

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/audit-7.1-gadget-outer-prefixes.py"
spec = importlib.util.spec_from_file_location("chest_gadget_outer_prefix_71", SCRIPT)
outer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(outer)


class TestGadgetOuterPrefix71(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = json.loads(outer.OUTPUT.read_text(encoding="utf-8"))

    def test_observed_source_bound_population_snapshot(self):
        report = self.expected
        obs = report["observations"]
        self.assertEqual(report["source"]["rawExportSha256"], outer.RAW_SHA256)
        self.assertEqual(obs["rowCount"], outer.ROW_COUNT)
        self.assertEqual(obs["distinctFirstTwoByteValues"], 12)
        self.assertEqual(obs["distinctPrefixLengths"], 20)
        self.assertEqual(obs["parentPrefixBytesIncludingIds"], 831612)
        self.assertEqual(obs["candidateIdBytes"], 4 * outer.ROW_COUNT)
        self.assertEqual(obs["uninterpretedPrefixBytes"], 709216)
        controls = obs["candidateControlWordHistogram"]
        self.assertEqual(len(controls), 12)
        self.assertEqual(sum(group["rows"] for group in controls.values()), outer.ROW_COUNT)
        self.assertEqual(
            sum(group["totalPrefixBytesIncludingCandidateId"] for group in controls.values()),
            obs["parentPrefixBytesIncludingIds"])
        for key, group in controls.items():
            self.assertEqual(
                (int(group["rawFirstTwoBytesLe"], 16) + outer.CANDIDATE_CONTROL_ADD) & 0xffff,
                int(key, 16))
            counts = group["prefixLengthHistogram"]
            self.assertEqual(sum(counts.values()), group["rows"])
            self.assertEqual(
                sum(int(n) * count for n, count in counts.items()),
                group["totalPrefixBytesIncludingCandidateId"])
        self.assertEqual(controls["0x0004"]["rows"], 22913)
        self.assertEqual(controls["0x0084"]["rows"], 6113)
        self.assertEqual(controls["0xFFFE"]["prefixLengthHistogram"], {"10": 19})
        self.assertEqual(obs["chestSubsetRows"], 309)
        self.assertEqual(
            {k: group["rows"] for k, group in obs["chestSubsetCandidateControlHistogram"].items()},
            {"0x0004": 134, "0x0084": 175})
        self.assertEqual(obs["chestSubsetCandidateControlHistogram"]["0x0084"]
                         ["prefixLengthHistogram"], {"47": 4, "48": 171})

    def test_synthetic_control_word_and_chest_subset(self):
        # Outer prefixes deliberately use different lengths. The raw inner
        # payload is a placeholder, since this helper only groups the spans.
        first = b"\x91\xab" + b"\0" * 10 + b"\x01\0\0\0"
        second = b"\x8f\xab" + b"\0" * 12 + b"\x02\0\0\0"
        data = b"head" + first + b"\0" * 8 + second + b"\0" * 8
        first_inner_start = 4 + len(first)
        second_start = first_inner_start + 8
        second_inner_start = second_start + len(second)
        rows = (
            GadgetRow(70210001, first_inner_start - 4, first_inner_start,
                      first_inner_start + 8, 4, 0, {0x6C: 26}, {}),
            GadgetRow(41023012, second_inner_start - 4, second_inner_start,
                      second_inner_start + 8, second_start, 0, {}, {}),
        )
        scan = GadgetTableScan(data[:4].hex(), rows, len(data),
                               len(first) + len(second))
        obs = outer.observe(scan, data)["observations"]
        self.assertEqual(obs["rowCount"], 2)
        self.assertEqual(obs["distinctFirstTwoByteValues"], 2)
        self.assertEqual(obs["chestSubsetRows"], 1)
        self.assertEqual(
            obs["chestSubsetCandidateControlHistogram"]["0x0004"]["exampleGadgetIdCandidate"],
            70210001)
        self.assertEqual(obs["candidateControlWordHistogram"]["0x0002"]
                         ["prefixLengthHistogram"], {"18": 1})

    def test_source_gate_and_invalid_prefix_rejected(self):
        with self.assertRaisesRegex(ValueError, "size or SHA-256"):
            outer.audit(b"wrong original source")
        with self.assertRaisesRegex(ValueError, "size or SHA-256"):
            outer.audit(bytes(outer.RAW_BYTES))
        data = b"head" + b"\0" * 8
        bad = GadgetRow(1, 4, 8, 12, 4, 0, {}, {})
        scan = GadgetTableScan(data[:4].hex(), (bad,), len(data), 4)
        with self.assertRaisesRegex(ValueError, "invalid outer prefix"):
            outer.observe(scan, data)


if __name__ == "__main__":
    unittest.main()
