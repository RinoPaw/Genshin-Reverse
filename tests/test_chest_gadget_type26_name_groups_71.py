"""Regression for original 7.1 Gadget type26 literal names, not chest rewards."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/audit-7.1-native-gadget-type26-names.py"
spec = importlib.util.spec_from_file_location("native_type26_71", SCRIPT)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class TestGadgetType26Names71(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = json.loads(tool.OUTPUT.read_text(encoding="utf-8"))

    def test_source_bound_counts_are_literal_and_partition_all_rows(self):
        result = self.expected
        self.assertEqual(result["source"]["rawExportSha256"], tool.RAW_SHA)
        self.assertEqual(result["source"]["payloadSha256"], tool.PAYLOAD_SHA)
        observed = result["observed"]
        self.assertEqual(observed["allGadgetDefinitions"], 30599)
        self.assertEqual(observed["nativeType26Definitions"], 309)
        self.assertEqual(observed["distinctNameStrings"], 148)
        groups = observed["groups"]
        self.assertEqual({g: x["records"] for g, x in groups.items()}, {
            "literal_SceneObj_Chest_prefix": 162,
            "literal_SearchPoint_prefix": 21,
            "other_literal_names": 126,
        })
        self.assertEqual(sum(x["records"] for x in groups.values()), 309)
        self.assertEqual(sum(x["distinctLiteralNames"] for x in groups.values()), 148)
        self.assertEqual(sum(x["withLiteralLv1ThroughLv5Suffix"]
                             for x in groups.values()), 86)
        self.assertEqual(observed["embeddedSearchPointOutsideLiteralPrefix"], 2)
        self.assertIn("REWARD_CLASSIFICATION_UNVERIFIED", result["status"])
        self.assertNotIn("dropTag", result)
        self.assertNotIn("rewardGrade", result)

    def test_synthetic_prefixes_and_fail_closed_missing_name(self):
        names = ["SceneObj_Chest_Default_Lv1"] * 162 + [
            "SearchPoint"] * 21 + ["SceneObj_Desert_DeshretRune"] * 126
        scan = SimpleNamespace(rows=[
            SimpleNamespace(gadget_id=70000000 + idx, base_mask=0x17,
                            mask=0x4000000, fields={
                                0x6C: 26, 0x58: name, 0x78: True})
            for idx, name in enumerate(names)])
        report, detail = tool.analyze(scan)
        counts = report["observed"]["groups"]
        self.assertEqual([counts[k]["records"] for k in (
            "literal_SceneObj_Chest_prefix", "literal_SearchPoint_prefix",
            "other_literal_names")], [162, 21, 126])
        self.assertEqual(len(detail), 309)
        self.assertEqual(detail[0]["preWrapperWireKey"], 70000000)
        self.assertEqual(detail[0]["nativeFieldsByCandidateMemoryOffset"]["0x6C"], 26)
        self.assertEqual(detail[-1]["nativeNameGroup"], "other_literal_names")
        scan.rows[0].fields.pop(0x58)
        with self.assertRaisesRegex(ValueError, "name missing"):
            tool.analyze(scan)

    def test_rejects_wrong_or_truncated_client_export(self):
        with self.assertRaisesRegex(ValueError, "SHA-256/size"):
            tool.audit(b"unverified asset")
        with self.assertRaisesRegex(ValueError, "SHA-256/size"):
            tool.audit(bytes(tool.SOURCE_BYTES))


if __name__ == "__main__":
    unittest.main()
