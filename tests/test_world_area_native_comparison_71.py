from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "scripts/compare-7.1-native-world-area.py"
spec = importlib.util.spec_from_file_location("world_area_native_compare_71", SOURCE)
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)


class WorldAreaNativeComparisonTests(unittest.TestCase):
    @staticmethod
    def _v(x, z, y=None):
        return {"coordinates": {"x": x, "y": y, "z": z}}

    @staticmethod
    def _p(x, z, y=None):
        result = {"_x": x, "_z": z}
        if y is not None:
            result["_y"] = y
        return result

    def _native_record(self, area1, area2=None, point_count=3):
        coordinates = [self._v(i, i) for i in range(point_count)]
        return {
            "offset_0x18_u32": area1, "offset_0x1C_u32": area2,
            "offset_0x10_shape": {
                "offset_0x18_vertices": {"points": coordinates},
                "offset_0x24_vector": {"coordinates": {"y": -10}},
                "offset_0x30_vector": {"coordinates": {"y": 10}},
            },
        }

    def _community_record(self, area1, area2=None, point_count=3):
        record = {
            "BBLLBIOLMHP": area1,
            "JLFEAGHGCLP": {
                "BFLLDPOAJGD": [self._p(i, i) for i in range(point_count)],
                "MHLOLALFHHF": {"_y": -10},
                "NFFDCMLAAFO": {"_y": 10},
            },
        }
        if area2 is not None:
            record["EOIFEEDBAFJ"] = area2
        return record

    def _scene(self, native_child_points=3, community_child_points=3):
        native = {"parents": [{
            "area_record": self._native_record(25),
            "child_array": {"values": [self._native_record(25, 2503, native_child_points)]},
        }]}
        community = {"OBKNAJCIHEA": [{
            "LKBLPFHOAFB": self._community_record(25),
            "OPHHFKKPLDI": [self._community_record(25, 2503, community_child_points)],
        }]}
        return native, community

    def test_identical_geometry_matches(self):
        n, c = self._scene()
        result = comparison.compare_scene(n, c, 3)
        self.assertEqual(0, result["differenceCount"])
        self.assertEqual(6, result["nativeVertexCount"])

    def test_extra_native_vertices_are_attributed_to_specific_child(self):
        n, c = self._scene(native_child_points=5)
        result = comparison.compare_scene(n, c, 3)
        self.assertEqual(2, result["nativeVertexCount"] - result["communityVertexCount"])
        self.assertEqual([{
            "record": "child:25:2503:0", "kind": "VERTEX_COUNT",
            "native": 5, "community": 3,
        }], result["differences"])

    def test_height_bound_mismatch_is_detected_independently(self):
        n, c = self._scene()
        n["parents"][0]["area_record"]["offset_0x10_shape"]["offset_0x30_vector"][
            "coordinates"]["y"] = 11
        result = comparison.compare_scene(n, c, 3)
        self.assertEqual(1, result["differenceCount"])
        self.assertEqual("HEIGHT_BOUND", result["differences"][0]["kind"])


if __name__ == "__main__":
    unittest.main()
