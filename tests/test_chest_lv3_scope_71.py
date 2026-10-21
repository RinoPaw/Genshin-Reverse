"""Keep original-client 7.1 Lv3 coverage separate from historical four-grade scans."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import re
import runpy
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/audit-7.1-chest-lv3-scope.py"
REPORT = ROOT / "versions/7.1.0-global/analyses/progression/economy/7.1-chest-native-gadget-prefab-controls.json"
spec = importlib.util.spec_from_file_location("chest_lv3_scope_71", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ChestLv3ScopeTests(unittest.TestCase):
    def setUp(self):
        self.native = json.loads(REPORT.read_text(encoding="utf-8"))
        self.regex = runpy.run_path(str(ROOT / "scripts/audit-7.1-legacy-chest-sources.py"))["PREFAB"]

    def test_original_client_five_suffixes_are_not_four_grade_scope(self):
        data = module.audit(self.native, self.regex)
        self.assertEqual(data["historicalFourGradeFilterMatches"], 16)
        self.assertEqual(data["historicalFourGradeFilterExcludes"], 4)
        self.assertEqual(data["excludedNativeIds"], [70210031, 70210032, 70210033, 70210034])
        self.assertEqual(data["excludedNativeSuffixes"], [3])

    def test_rejects_mutated_name_and_duplicate_source_id(self):
        bad = copy.deepcopy(self.native)
        bad["controls"]["nativeNameFields"][8]["nativeNameString"] = "SceneObj_Chest_Default_Lv2"
        with self.assertRaisesRegex(ValueError, "original native name"):
            module.audit(bad, self.regex)
        bad = copy.deepcopy(self.native)
        bad["controls"]["nativeNameFields"][1]["gadgetIdPreWrapperScalar"] = 70210011
        with self.assertRaisesRegex(ValueError, "duplicate"):
            module.audit(bad, self.regex)

    def test_expanding_historical_selector_requires_review(self):
        widened = re.compile(r"^SceneObj_Chest_(Default|Locked|Bramble|Frozen)_Lv[1-5]$")
        with self.assertRaisesRegex(ValueError, "re-audit"):
            module.audit(self.native, widened)


if __name__ == "__main__":
    unittest.main()
