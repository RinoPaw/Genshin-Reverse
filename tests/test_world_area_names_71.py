"""Regression contract for the pinned WorldArea CHS localization recovery."""
from __future__ import annotations
import json
from pathlib import Path
import unittest

BASE = Path(__file__).resolve().parents[1] / "versions/7.1.0-global/analyses/progression/world"


class WorldAreaNamesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = json.loads((BASE / "7.1-world-area-names-chs.json").read_text(encoding="utf-8"))
        cls.rows = cls.source["areas"]
        cls.index = {(r["sceneID"], r["areaID1"], r["areaID2"]): r for r in cls.rows}

    def test_all_578_source_hashes_accounted_for(self):
        self.assertEqual(len(self.rows), 578)
        self.assertEqual(len(self.index), 578)
        self.assertEqual(self.source["nameSources"], {"medium": 550, "missing": 28})
        self.assertEqual(sum(r["name"] is None for r in self.rows), 28)
        self.assertEqual(sum(r["name"] is not None for r in self.rows), 550)

    def test_old_regions_resolved_without_guesses(self):
        for city, expected in ((1, 35), (2, 65)):
            with self.subTest(city=city):
                rows = [r for r in self.rows if r["cityId"] == city]
                self.assertEqual(len(rows), expected)
                self.assertTrue(all(r["name"] is not None for r in rows))
                self.assertTrue(all(r["textMapSource"] == "medium" for r in rows))

    def test_pinned_independent_sources(self):
        source = self.source["provenance"]
        self.assertEqual(source["locale"], "CHS")
        self.assertIn("MeChen618/AstaPS-Resource@", source["areaConfig"])
        self.assertIn("DimbreathBot/AnimeGameData@", source["textMap"])
        self.assertTrue(all(r["textMapSource"] in ("medium", "missing") for r in self.rows))

    def test_exact_higher_reward_geographic_names(self):
        names = {
            (3, 1, 104): "望风山地",
            (3, 10, 0): "龙脊雪山",
            (3, 7, 703): "孤云阁",
            (3, 8, 0): "璃沙郊",
            (3, 19, 0): "层岩巨渊",
            (6, 300, 0): "层岩巨渊·地下矿区",
            (3, 18, 0): "鹤观",
            (3, 77, 0): "风息山",
            (3, 40, 0): "沉玉谷·上谷",
            (3, 41, 0): "沉玉谷·南陵",
            (3, 47, 0): "来歆山",
        }
        for key, name in names.items():
            with self.subTest(key=key):
                self.assertEqual(self.index[key]["name"], name)

    def test_no_known_native_geometry_change_affects_old_reward_selectors(self):
        delta = json.loads((BASE / "7.1-native-world-area-geometry-delta.json").read_text(encoding="utf-8"))
        changes = {(delta["changedScene"]["sceneID"], x["areaID1"], x["areaID2"])
                   for x in delta["changedScene"]["changes"]}
        known_higher = {(3, 1, 104), (3, 7, 703)}
        self.assertFalse(changes.intersection(known_higher))
        self.assertEqual({scene for scene, _, _ in changes}, {3})
        self.assertTrue({parent for _, parent, _ in changes} <= {55, 56, 57, 58})


if __name__ == "__main__":
    unittest.main()
