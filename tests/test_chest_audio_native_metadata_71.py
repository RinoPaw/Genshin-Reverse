"""Metadata token hypotheses must never directly become native loot semantics."""
from __future__ import annotations

import csv
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/probe-7.1-chest-audio-native-metadata.py"
spec = importlib.util.spec_from_file_location("chest_audio_metadata", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ChestAudioMetadataTests(unittest.TestCase):
    def setUp(self):
        self.context = tempfile.TemporaryDirectory()
        self.addCleanup(self.context.cleanup)
        root = Path(self.context.name)
        self.fields = root / "fields.csv"
        self.methods = root / "methods.csv"

    @staticmethod
    def csvfile(path: Path, headers, rows):
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, headers)
            writer.writeheader()
            writer.writerows(rows)

    def seed(self, *, same_owner=True):
        self.csvfile(self.fields, ("field_index", "type_definition_index", "type_name",
                    "field_name", "field_type", "field_type_index", "offset"), [
            {"field_index": "1", "type_definition_index": "21", "type_name": "NATIVEA",
             "field_name": "AIMCCDKDAKB", "field_type": "uint32", "field_type_index": "99",
             "offset": "0x18"},
            {"field_index": "2", "type_definition_index": "21" if same_owner else "24",
             "type_name": "NATIVEA" if same_owner else "NATIVEB",
             "field_name": "DMNAJDGMHDE", "field_type": "string", "field_type_index": "100",
             "offset": "0x28"},
        ])
        self.csvfile(self.methods, ("method_index", "type_definition_index", "type_name",
                    "method_name", "rva", "return_type", "parameter_types"), [
            {"method_index": "111", "type_definition_index": "21", "type_name": "NATIVEA",
             "method_name": "GMENPOPMKAA", "rva": "0x1234", "return_type": "void",
             "parameter_types": "FNIAHJGHFAK"},
        ])

    def test_two_obfuscated_names_same_owner_only_a_lead(self):
        self.seed()
        report = mod.inspect(self.fields, self.methods, require_original=False)
        self.assertEqual(report["ownerWithBothTokens"], ["21"])
        self.assertEqual(report["ownerCandidates"]["21"]["methods"][0]["rva"], "0x1234")
        self.assertTrue(report["ownerCandidates"]["21"]["methods"][0]
                        ["candidateBinReaderSignature"])
        self.assertNotIn("rewardGrade", report)

    def test_separate_owners_must_not_be_assumed_coincident(self):
        self.seed(same_owner=False)
        report = mod.inspect(self.fields, self.methods, require_original=False)
        self.assertEqual(report["ownerWithBothTokens"], [])
        self.assertEqual(report["fieldTokenHitCounts"],
                         {"AIMCCDKDAKB": 1, "DMNAJDGMHDE": 1})

    def test_exact_source_gate_and_duplicate_are_fail_closed(self):
        self.seed()
        with self.assertRaisesRegex(ValueError, "Git blob mismatch"):
            mod.inspect(self.fields, self.methods)
        with self.fields.open("a", encoding="utf-8") as stream:
            stream.write("3,21,NATIVEA,AIMCCDKDAKB,uint32,99,0x30\n")
        with self.assertRaisesRegex(ValueError, "duplicate source token"):
            mod.inspect(self.fields, self.methods, require_original=False)

    def test_absence_has_no_semantic_conclusion(self):
        self.seed()
        self.csvfile(self.fields, ("field_index", "type_definition_index", "type_name",
                    "field_name", "field_type", "field_type_index", "offset"), [])
        report = mod.inspect(self.fields, self.methods, require_original=False)
        self.assertEqual(report["ownerCandidates"], {})
        self.assertEqual(report["ownerWithBothTokens"], [])


if __name__ == "__main__":
    unittest.main()
