"""Original 7.1 prefab ID identity versus historical Gadget instance attributes."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "reward_gadget_discriminators", ROOT / "scripts/audit-7.1-reward-gadget-discriminators.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
NATIVE = json.loads(mod.CONTROL.read_text(encoding="utf-8"))


def row(gid, tag, idx, source="drop_tag"):
    return {
        "scene": "3", "file": f"Scripts/Scene/3/scene3_group{idx}.lua",
        "config_id": str(idx), "gadget_id": str(gid),
        "x": "100", "y": "5", "z": "200",
        "source": source, "drop_tag": tag, "chest_drop_id": "",
        "lua_area_id": "1", "city_id": "1", "area1": "1",
        "area2": "2", "lookup_status": "matched",
        "source_region": "蒙德", "source_grade": "低级",
        "is_oneoff": "True", "persistent": "True",
        "explore_chest": "False",
    }


class RewardGadgetDiscriminatorTests(unittest.TestCase):
    def test_native_20_original_name_controls(self):
        self.assertEqual(mod.native_ids(NATIVE), mod.EXPECTED_CORE)
        self.assertEqual(len(mod.EXPECTED_CORE), 20)
        self.assertIn(70210031, mod.native_ids(NATIVE))

    def test_single_gadget_can_have_three_sources_and_different_tags(self):
        a = row(70210101, "搜刮点解谜通用稻妻", 1)
        b = row(70210101, "", 2, "explicit_id")
        b["chest_drop_id"] = "1000100"
        c = row(70210101, "", 3, "no_metadata")
        c["is_oneoff"] = "False"
        d = row(70210101, "搜刮点解谜通用璃月", 4)
        result = mod.audit([a, b, c, d], NATIVE, full=False)
        stats = result["historicalScene"]
        self.assertEqual(stats["gadgetIdsWithAllThreeSourceKinds"], 1)
        self.assertEqual(stats["gadgetIdsWithMultipleDropTags"], 1)
        self.assertEqual(stats["ambiguousIds"]["70210101"]["distinctDropTags"], 2)
        self.assertFalse(stats["perInstanceLevelAvailableInThisCSV"])

    def test_do_not_auto_infer_grade_from_prefix_or_lv(self):
        result = mod.audit([row(70211101, "解谜中级璃月", 1)], NATIVE, full=False)
        self.assertEqual(result["historicalScene"]["gadgetIdsWithMultipleChineseGradeSubstrings"], 0)
        self.assertFalse(result["nativeGlobal71"]["originalPlacementOrOfficialLootGradeProven"])
        self.assertTrue(any("three different" in msg for msg in result["cannotDerive"]))

    def test_mismatched_native_identity_is_rejected(self):
        control = copy.deepcopy(NATIVE)
        control["controls"]["nativeNameFields"][0]["gadgetIdPreWrapperScalar"] = 1
        with self.assertRaisesRegex(ValueError, "20 Gadget"):
            mod.native_ids(control)
        control = copy.deepcopy(NATIVE)
        control["controls"]["nativeNameFields"][0]["nativeNameString"] = "fake"
        with self.assertRaisesRegex(ValueError, "prefab name pattern"):
            mod.native_ids(control)

    def test_ambiguity_and_source_input_guards(self):
        a = row(70210101, "搜刮点解谜通用璃月", 1)
        with self.assertRaisesRegex(ValueError, "duplicate historical"):
            mod.audit([a, copy.deepcopy(a)], NATIVE, full=False)
        bad = row(70210101, "搜刮点解谜通用璃月", 1)
        bad["source"] = "new-unknown-kind"
        with self.assertRaisesRegex(ValueError, "unknown historical"):
            mod.audit([bad], NATIVE, full=False)
        bad = row(70210101, "搜刮点解谜通用璃月", 1)
        bad["is_oneoff"] = "unknown"
        with self.assertRaisesRegex(ValueError, "oneoff"):
            mod.audit([bad], NATIVE, full=False)


if __name__ == "__main__":
    unittest.main()
