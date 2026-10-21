"""Keep original 7.1 native audio integer classes distinct from public labels."""
from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/audit-7.1-chest-audio-public-association.py"
spec = importlib.util.spec_from_file_location("chest_audio_association", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def fixtures():
    values = [None] * 21 + [1] * 12 + [2] * 12 + [3] * 11
    native = {
        "sourceRawSha256": mod.NATIVE_RAW_SHA, "status": mod.NATIVE_STATUS,
        "nativeHeaderCount": 56, "decodedRecords": 56,
        "uniquePreWrapperGadgetKeyScalars": 56,
        "payloadBytes": 480, "unparsedBytes": 0,
        "rows": [
            {"gadgetIdPreWrapperScalar": 70210001 + i,
             "nativeClassScalar": value,
             "nativeClassFieldPresent": value is not None}
            for i, value in enumerate(values)
        ],
    }
    public = [
        {"AIMCCDKDAKB": 70210001 + i,
         **({"DMNAJDGMHDE": {1: "Mid", 2: "Hi", 3: "Top"}[value]}
            if value is not None else {})}
        for i, value in enumerate(values)
    ]
    return native, public


class ChestAudioAssociationTests(unittest.TestCase):
    def test_full_56_row_class_and_presence_association(self):
        native, public = fixtures()
        report = mod.compare(native, public)
        self.assertEqual(report["matchedDistinctNativePreWrapperGadgetScalars"], 56)
        self.assertEqual([r["matchingRows"] for r in report["nativeValueToPublicLabelPairs"]],
                         [21, 12, 12, 11])
        self.assertEqual(report["nativeScalarsWithMultiplePublicLabels"], [])

    def test_missing_key_duplicate_and_presence_drift_fail(self):
        native, public = fixtures()
        bad = copy.deepcopy(public)
        bad[0]["AIMCCDKDAKB"] = -1
        with self.assertRaisesRegex(ValueError, "key sets differ"):
            mod.compare(native, bad)
        bad = copy.deepcopy(public)
        bad[0]["AIMCCDKDAKB"] = bad[1]["AIMCCDKDAKB"]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            mod.compare(native, bad)
        bad_native = copy.deepcopy(native)
        bad_native["rows"][21]["nativeClassFieldPresent"] = False
        with self.assertRaisesRegex(ValueError, "presence status"):
            mod.compare(bad_native, public)

    def test_unsupported_label_variation_stays_explicit(self):
        native, public = fixtures()
        public[-1]["DMNAJDGMHDE"] = "Other"
        report = mod.compare(native, public)
        self.assertEqual(report["nativeScalarsWithMultiplePublicLabels"], ["3"])
        self.assertNotIn("serverRewardClass", report)

    def test_source_hash_guard(self):
        with self.assertRaisesRegex(ValueError, "Git blob mismatch"):
            mod.original_public_json(b"[]")


if __name__ == "__main__":
    unittest.main()
