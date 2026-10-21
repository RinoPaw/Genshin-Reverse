"""Original Global 7.1 Gadget-only selector boundary regression."""
from importlib import util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/audit-7.1-native-gadget-selector-boundary.py"
_spec = util.spec_from_file_location("gadget_selector_native_71", SCRIPT)
_module = util.module_from_spec(_spec)
_spec.loader.exec_module(_module)


class NativeGadgetSelectorBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = json.loads(_module.SOURCE.read_text(encoding="utf-8"))
        cls.actual = _module.audit(source)

    def test_published_source_bound_report(self):
        self.assertEqual(
            self.actual,
            json.loads(_module.OUTPUT.read_text(encoding="utf-8")))
        self.assertEqual(self.actual["source"]["originalRawSha256"], _module.RAW_SHA)

    def test_literal_lv_suffix_has_constant_distinct_integer(self):
        rows = self.actual["observations"]["canonicalLiteralLvControls"]
        self.assertEqual(len(rows), 20)
        self.assertEqual({r["literalLvSuffix"] for r in rows}, {1, 2, 3, 4, 5})
        self.assertEqual({r["offset0x84"] for r in rows}, {2})
        self.assertEqual({r["inherited0x18"] for r in rows}, {5001})

    def test_presence_and_ambiguous_names(self):
        obs = self.actual["observations"]
        self.assertEqual(
            obs["numeric26Offset0x84Counts"],
            {"1": 97, "2": 21, "4": 29, "absent": 162})
        self.assertEqual(len(obs["normalChestLiteralSix"]), 6)
        self.assertEqual(obs["normalChestLiteralSix"][-1]["offset0x84"], "absent")
        self.assertEqual(len(obs["sameLiteralDefaultLv4"]), 8)
        self.assertEqual(len(obs["repeatedLiteralNamesWithDifferent0x84"]), 11)
        self.assertEqual(len(obs["namedSceneObjChestOutsideNumeric26"]), 5)

    def test_fail_closed_on_wrong_source(self):
        source = json.loads(_module.SOURCE.read_text(encoding="utf-8"))
        source["source"]["rawSha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "unverified"):
            _module.audit(source)


if __name__ == "__main__":
    unittest.main()
