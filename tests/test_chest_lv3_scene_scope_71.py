"""Historical scene coverage scope: no native 7.1 placement claims."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/audit-7.1-chest-lv3-scene-scope.py"
spec = importlib.util.spec_from_file_location("chest_lv3_scene_scope_71", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
NATIVE = json.loads(module.NATIVE.read_text(encoding="utf-8"))


def source_summary():
    return {
        "pinned_source": {
            "resource_repository": "MeChen618/AstaPS-Resource",
            "resource_commit": module.RESOURCE_COMMIT,
            "scanner_repository": "RinoPaw/AstaPS",
            "scanner_commit": module.SCANNER_COMMIT,
        },
        "totals": {"ordinary_chests": module.EXPECTED_RECORDS,
                   "lua_files": 41110, "excluded_boss": 43},
    }


def rows_with(ids=()):
    ids = list(ids)
    rows = []
    for i in range(module.EXPECTED_RECORDS):
        gid = ids[i] if i < len(ids) else 70211101
        rows.append({
            "scene": "3", "file": "Scripts/Scene/3/scene3_group1.lua",
            "config_id": str(i + 1), "gadget_id": str(gid),
            "source": "drop_tag", "drop_tag": "解谜低级蒙德",
            "source_grade": "低级",
        })
    return rows


class ChestLv3SceneScopeTests(unittest.TestCase):
    def test_zero_core_ids_are_bounded_to_scene_resource(self):
        result = module.audit(rows_with(), source_summary(), NATIVE)
        self.assertEqual(result["sceneCandidateRecords"], 14084)
        self.assertEqual(result["originalClientCoreDefinitionsChecked"], 20)
        self.assertTrue(all(x == 0 for x in
                            result["originalClientCoreDefinitionInstanceCounts"].values()))
        self.assertEqual(result["lv3OriginalClientDefinitionInstanceCounts"],
                         {str(i): 0 for i in range(70210031, 70210035)})
        self.assertEqual(result["legacySourceSpecificGadgetSample"]["puzzle"][0]
                         ["instanceCount"], 14084)

    def test_nonzero_lv3_is_reported_without_relabeling_grade(self):
        gids = [70210031, 70210032, 70210033, 70210034, 70211001]
        result = module.audit(rows_with(gids), source_summary(), NATIVE)
        self.assertEqual(list(result["lv3OriginalClientDefinitionInstanceCounts"].values()),
                         [1, 1, 1, 1])
        self.assertEqual(result["legacySourceSpecificGadgetSample"]["combat"][0]
                         ["gradeFromHistoricalDropTag"], {"低级": 1})
        self.assertNotIn("officialGrade", result)

    def test_source_drift_fails(self):
        bad = source_summary()
        bad["pinned_source"]["scanner_commit"] = "bad"
        with self.assertRaisesRegex(ValueError, "input revision changed"):
            module.audit(rows_with(), bad, NATIVE)
        with self.assertRaisesRegex(ValueError, "record count changed"):
            module.audit(rows_with()[:100], source_summary(), NATIVE)
        bad = copy.deepcopy(NATIVE)
        bad["controls"]["nativeNameFields"][0]["gadgetIdPreWrapperScalar"] = 9
        with self.assertRaisesRegex(ValueError, "20-ID"):
            module.audit(rows_with(), source_summary(), bad)

    def test_csv_schema_rejects_nondecimal_id(self):
        rows = rows_with()
        rows[0]["gadget_id"] = "70x"
        with self.assertRaisesRegex(ValueError, "nondecimal"):
            module.audit(rows, source_summary(), NATIVE)

    def test_summary_digest_requires_exact_bytes(self):
        raw = b'{"status": "unverified"}'
        digest = hashlib.sha256(raw).hexdigest()
        self.assertEqual(module.pinned_json(raw, digest), {"status": "unverified"})
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            module.pinned_json(raw + b" ", digest)


if __name__ == "__main__":
    unittest.main()
