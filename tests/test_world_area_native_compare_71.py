from __future__ import annotations

import unittest

from genshinre.worldareacompare import compare_scene


def v(x,z,y=None):
    return {"coordinates":{"x":x,"y":y,"z":z}}


def shape(points,minimum=-1000,maximum=1000):
    return {
        "offset_0x18_vertices":{"points":[v(x,z) for x,z in points]},
        "offset_0x24_vector":{"coordinates":{"x":0,"y":minimum,"z":0}},
        "offset_0x30_vector":{"coordinates":{"x":0,"y":maximum,"z":0}},
    }


def oldshape(points,minimum=-1000,maximum=1000):
    return {"JLFEAGHGCLP":{
        "BFLLDPOAJGD":[{"_x":x,"_z":z} for x,z in points],
        "MHLOLALFHHF":{"_y":minimum},
        "NFFDCMLAAFO":{"_y":maximum},
    }}


def fixture(changed=False):
    parent_points=[(0.,0.),(10.,0.),(10.,10.)]
    children=[(1.,1.),(2.,1.),(2.,2.)]
    if changed: children=children+[(1.,2.)]
    native={"parents":[{
        "area_record":{
            "offset_0x18_u32":210, "offset_0x10_shape":shape(parent_points),
        },
        "child_array":{"values":[{
            "offset_0x18_u32":210, "offset_0x1C_u32":21001,
            "offset_0x10_shape":shape(children),
        }]},
    }]}
    source={"OBKNAJCIHEA":[{
        "LKBLPFHOAFB":{"BBLLBIOLMHP":210,**oldshape(parent_points)},
        "OPHHFKKPLDI":[{
            "BBLLBIOLMHP":210, "EOIFEEDBAFJ":21001,
            **oldshape([(1.,1.),(2.,1.),(2.,2.)]),
        }],
    }]}
    return native,source


class NativeWorldAreaCompareTests(unittest.TestCase):
    def test_matching_records_and_coordinates(self):
        result=compare_scene(*fixture(),7)
        self.assertTrue(result["parentChildIdSequenceMatches"])
        self.assertEqual(0,result["changedGeometryCount"])
        self.assertEqual([],result["nativeExtraChildIds"])
        self.assertEqual({"community":6,"native7_1":6,"delta":0},
                         result["vertices"])

    def test_vertex_addition_is_reported_without_inventing_community_data(self):
        result=compare_scene(*fixture(changed=True),7)
        self.assertEqual(1,result["changedGeometryCount"])
        changed=result["changedGeometry"][0]
        self.assertEqual({"level":2,"areaID1":210,"areaID2":21001},
                         {k:changed[k] for k in ("level","areaID1","areaID2")})
        self.assertEqual(["vertex_count"],changed["issues"])
        self.assertEqual({"community":6,"native7_1":7,"delta":1},
                         result["vertices"])

    def test_id_mismatch_is_not_hidden(self):
        native,old=fixture()
        native["parents"][0]["child_array"]["values"][0]["offset_0x1C_u32"]=99001
        result=compare_scene(native,old,7)
        self.assertFalse(result["parentChildIdSequenceMatches"])
        self.assertEqual([[210,99001]],result["nativeExtraChildIds"])
        self.assertEqual([[210,21001]],result["communityExtraChildIds"])


if __name__ == "__main__":
    unittest.main()
