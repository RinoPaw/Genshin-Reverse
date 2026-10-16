"""Focused synthetic tests for the reusable chest -> WorldArea classifier."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import unittest

MODULE = Path(__file__).resolve().parents[1] / "scripts/audit-7.1-chest-regions.py"
spec = importlib.util.spec_from_file_location("audit_chest_regions_71", MODULE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def poly(coords, lower=-1000, upper=1000):
    return {
        "JLFEAGHGCLP": {
            "BFLLDPOAJGD": [{"_x": x, "_z": z} for x, z in coords],
            "MHLOLALFHHF": {"_y": lower},
            "NFFDCMLAAFO": {"_y": upper},
        }
    }


class TestChestRegions(unittest.TestCase):
    def test_polygon_boundary_and_position(self):
        square = [{"_x": x, "_z": z} for x, z in [(0, 0), (10, 0), (10, 10), (0, 10)]]
        self.assertTrue(module.inside(square, 5, 5))
        self.assertFalse(module.inside(square, 20, 5))

    def test_parent_first_child_first_height(self):
        parent = poly([(0, 0), (100, 0), (100, 100), (0, 100)])
        low = poly([(0, 0), (100, 0), (100, 100), (0, 100)], 0, 9)
        high = poly([(0, 0), (100, 0), (100, 100), (0, 100)], 10, 20)
        block = {"LKBLPFHOAFB": {"BBLLBIOLMHP": 1, **parent},
                 "OPHHFKKPLDI": [
                     {"EOIFEEDBAFJ": 101, **low},
                     {"EOIFEEDBAFJ": 102, **high},
                 ]}
        self.assertEqual(module.choose([block], 50, 9, 50)["area2"], 101)
        self.assertEqual(module.choose([block], 50, 10, 50)["area2"], 102)
        self.assertEqual(module.choose([block], 50, 99, 50)["lookup_status"], "parent_only")
        self.assertEqual(module.choose([block], 200, 10, 50)["lookup_status"], "no_parent")

    def test_parent_gating_and_first_parent_wins(self):
        square = poly([(0, 0), (100, 0), (100, 100), (0, 100)])
        off_parent = poly([(200, 200), (300, 200), (300, 300), (200, 300)])
        first = {"LKBLPFHOAFB": {"BBLLBIOLMHP": 1, **square},
                 "OPHHFKKPLDI": [{"EOIFEEDBAFJ": 101, **off_parent}]}
        second = {"LKBLPFHOAFB": {"BBLLBIOLMHP": 2, **square},
                  "OPHHFKKPLDI": [{"EOIFEEDBAFJ": 201, **square}]}
        self.assertEqual(module.choose([first, second], 50, 1, 50)["area1"], 1)
        self.assertEqual(module.choose([first, second], 50, 1, 50)["area2"], 0)

    def test_missing_child_height_is_not_guessed(self):
        square = poly([(0, 0), (10, 0), (10, 10), (0, 10)])
        child = {"EOIFEEDBAFJ": 101, "JLFEAGHGCLP": {
            "BFLLDPOAJGD": square["JLFEAGHGCLP"]["BFLLDPOAJGD"]}}
        block = {"LKBLPFHOAFB": {"BBLLBIOLMHP": 1, **square},
                 "OPHHFKKPLDI": [child]}
        row = module.choose([block], 5, 5, 5)
        self.assertEqual(row["lookup_status"], "uncertain_height")
        self.assertEqual(row["area2"], 0)

    def test_region_to_city_is_unique(self):
        definitions = [{"MBOHIOJBBHO": "LEVEL_1", "areaID1": x} for x in (1, 2)]
        self.assertEqual(module.city_index([
            {"cityId": 10, "areaIdVec": [1]},
            {"cityId": 11, "areaIdVec": [2]}], definitions), {1: 10, 2: 11})
        with self.assertRaises(ValueError):
            module.city_index([
                {"cityId": 10, "areaIdVec": [1, 2]},
                {"cityId": 11, "areaIdVec": [2]}], definitions)


if __name__ == "__main__":
    unittest.main()
