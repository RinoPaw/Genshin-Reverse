"""Source-bound historical scene level parser; never original semantic tests."""
from importlib import util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=util.spec_from_file_location("pinned_historical_chest",ROOT/"scripts/audit-7.1-historical-scene-chest-levels.py")
mod=util.module_from_spec(spec)
spec.loader.exec_module(mod)


class HistoricalChestLevel(unittest.TestCase):
    def test_top_level_only_and_nested_level_ignored(self):
        self.assertEqual(mod.direct_level('{gadget_id=1, explore={ level=15 }, level=4 }'),("explicit",4))
        self.assertEqual(mod.direct_level('{gadget_id=1, explore={ level=15 }, other={level=3}}'),("missing",None))
        self.assertEqual(mod.direct_level('{gadget_id=1, level=0}'),("explicit",0))

    def test_quotes_and_comments_cannot_create_level(self):
        obj="""{ gadget_id=4, info="level=90", -- level=88
                   obj={comment='level=77'}, level = 6, }"""
        self.assertEqual(mod.direct_level(obj),("explicit",6))
        self.assertEqual(mod.direct_level("{gadget_id=4, level='six'}"),("malformed",None))
        self.assertEqual(mod.direct_level("{gadget_id=4, level=true}"),("malformed",None))

    def test_duplicates_are_rejected(self):
        with self.assertRaisesRegex(ValueError,"duplicate top-level"):
            mod.direct_level("{level=1, level=2}")

    def test_published_historical_source_distribution_and_native_boundary(self):
        import json
        report=json.loads((ROOT/"versions/7.1.0-global/analyses/progression/economy/7.1-historical-scene-chest-level-coverage.json").read_text(encoding="utf-8"))
        self.assertEqual(report["completeUnmodifiedSourceReportSha256"],
                         "8f30255c066a99a7858a83bbfb2fd34d8d95d4ba9d14fa7bbeffe66a2d61b2ba")
        counts=report["totals"]
        self.assertEqual(counts["chestCandidates"],mod.EXPECTED_HISTORICAL_CHESTS)
        self.assertEqual(counts["luaFiles"],mod.EXPECTED_LUA_FILES)
        self.assertEqual(counts["excludedBoss"],mod.EXPECTED_EXCLUDED_BOSS)
        self.assertEqual(counts["defaultJavaZero"]+counts["explicitNonzero"],
                         counts["chestCandidates"])
        self.assertEqual(sum(report["levelValueDistribution"].values()),
                         counts["chestCandidates"])
        self.assertEqual(report["levelValueDistribution"]["explicit:26"],6433)
        self.assertEqual(report["levelValueDistribution"]["missing"],2683)
        for name,group in report["bySource"].items():
            self.assertEqual(sum(group.values()),{"drop_tag":9020,"explicit_id":1339,"no_metadata":3725}[name])
        self.assertEqual(report["bySource"]["no_metadata"]["missing"],2683)
        self.assertEqual(report["missingByScene"],{"3":2600,"101":83})
        self.assertFalse(report["originalGlobal71ClientInstanceLevelVerified"])
        self.assertFalse(report["originalOfficialServerSceneOwnershipVerified"])

    def test_no_original_authority_from_historical_source(self):
        self.assertEqual(mod.RESOURCE_COMMIT,"85b81a691fcf3d9e8e7db50a8febc8f9043bc084")
        self.assertEqual(mod.EXPECTED_HISTORICAL_CHESTS,14084)

if __name__=="__main__":
    unittest.main()
