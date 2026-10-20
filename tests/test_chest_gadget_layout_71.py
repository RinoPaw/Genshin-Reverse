"""Regression tests for exact 7.1 native Gadget reader-to-field layout inference."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/correlate-7.1-gadget-reader-layout.py"
spec = importlib.util.spec_from_file_location("chest_gadget_layout_71", SCRIPT)
layout = importlib.util.module_from_spec(spec)
spec.loader.exec_module(layout)


class TestGadgetLayoutCandidate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(layout.SCHEMA.read_text(encoding="utf-8"))
        cls.reader = json.loads(layout.READER.read_text(encoding="utf-8"))

    def test_all_22_native_stores_map_to_one_candidate(self):
        result = layout.correlate(self.schema, self.reader)
        expected = json.loads(layout.OUTPUT.read_text(encoding="utf-8"))
        self.assertEqual(result, expected)
        self.assertEqual(result["result"]["matchedDirectStoreOffsets"], 22)
        self.assertEqual(result["assumptions"]["objectFieldBaseCandidate"], "0x48")
        self.assertEqual(len(result["result"]["mapping"]), 22)
        offsets = {x["fieldName"]: x["candidateInstanceOffset"]
                   for x in result["result"]["mapping"]}
        self.assertEqual(offsets["NGDGAAEHPHB"], "0x78")
        self.assertEqual(offsets["MECPCDBEFBG"], "0x7C")
        self.assertEqual(offsets["OLOLLKJCHHI"], "0x7F")
        self.assertNotIn("chestGrade", result)

    def test_changed_native_source_identity_fails_closed(self):
        changed = copy.deepcopy(self.reader)
        changed["source"]["metadataSha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "source identity"):
            layout.correlate(self.schema, changed)

    def test_unsupported_storage_width_and_changed_store_rejected(self):
        changed = copy.deepcopy(self.schema)
        changed["owners"]["60078"]["fields"][0]["type"] = "unresolved_abi_type"
        with self.assertRaisesRegex(ValueError, "unclassified"):
            layout.correlate(changed, self.reader)
        altered = copy.deepcopy(self.reader)
        altered["directStoresToR14"]["1"].pop("0x78")
        with self.assertRaisesRegex(ValueError, "matched 0 starts"):
            layout.correlate(self.schema, altered)

    def test_wrong_metadata_reader_method_rejected(self):
        changed = copy.deepcopy(self.schema)
        changed["owners"]["60078"]["methods"][1]["rva"] = "0xBAD"
        with self.assertRaisesRegex(ValueError, "reader identity"):
            layout.correlate(changed, self.reader)


if __name__ == "__main__":
    unittest.main()
