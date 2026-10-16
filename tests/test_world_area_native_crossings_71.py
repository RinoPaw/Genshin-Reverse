from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parents[1]
SOURCE = HERE / "scripts/audit-7.1-native-world-area-crossings.py"
spec = importlib.util.spec_from_file_location("native_world_area_crossing_71", SOURCE)
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class NativeWorldAreaCrossingTests(unittest.TestCase):
    @staticmethod
    def shape(points, low=-10, high=10):
        return {"offset_0x10_shape": {
            "offset_0x18_vertices": {"points": [
                {"coordinates": {"x": x, "z": z, "y": None}}
                for x, z in points
            ]},
            "offset_0x24_vector": {"coordinates": {"y": low}},
            "offset_0x30_vector": {"coordinates": {"y": high}},
        }}

    @staticmethod
    def rectangle(x0,z0,x1,z1):
        return [(x0,z0),(x1,z0),(x1,z1),(x0,z1)]

    def tree(self, child_points, child_id=21001):
        return {"parents": [
            {
                "area_record": {
                    "offset_0x18_u32": 210,
                    **self.shape(self.rectangle(0,0,10,10)),
                },
                "child_array": {"values": [{
                    "offset_0x18_u32": 210,
                    "offset_0x1C_u32": child_id,
                    **self.shape(child_points),
                }]},
            },
        ]}

    def test_positive_child_outside_parent_has_native_y_midpoint(self):
        row=native.scan_tree(self.tree(self.rectangle(8,2,12,8)),7)
        self.assertEqual(1,row["positiveCrossingRecords"])
        w=row["witnesses"][0]
        self.assertEqual(21001,w["areaID2"])
        self.assertIsNone(w["firstNativeParentAtWitness"])
        self.assertEqual(0,w["inBoundsYTestValue"])
        self.assertGreater(w["witness"]["margin"],0.25)

    def test_contained_child_is_not_a_positive_conflict(self):
        row=native.scan_tree(self.tree(self.rectangle(2,2,8,8)),7)
        self.assertEqual(0,row["positiveCrossingRecords"])

    def test_parent_mismatch_fails_closed(self):
        tree=self.tree(self.rectangle(8,2,12,8))
        tree["parents"][0]["child_array"]["values"][0]["offset_0x18_u32"]=999
        with self.assertRaisesRegex(ValueError,"parent mismatch"):
            native.scan_tree(tree,7)


if __name__=="__main__":
    unittest.main()
