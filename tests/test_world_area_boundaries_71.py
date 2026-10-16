import importlib.util
from pathlib import Path
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "scripts/audit-7.1-world-areas.py"
spec = importlib.util.spec_from_file_location("world_area_boundary_71", SOURCE)
world = importlib.util.module_from_spec(spec)
spec.loader.exec_module(world)


def square(x0, z0, x1, z1):
    return [
        {"_x": x0, "_z": z0}, {"_x": x1, "_z": z0},
        {"_x": x1, "_z": z1}, {"_x": x0, "_z": z1}
    ]


def child(id2, points, parent=1):
    return {
        "BBLLBIOLMHP": parent, "EOIFEEDBAFJ": id2,
        "JLFEAGHGCLP": {"BFLLDPOAJGD": points}
    }


class WorldAreaBoundaryResearchTest(unittest.TestCase):
    def test_absent_geometries_are_not_synthesized(self):
        config = [
            {"sceneID": 3, "MBOHIOJBBHO": "LEVEL_2",
             "areaID1": 1, "areaID2": id2,
             "ID": id2 + 1000, "areaNameTextMapHash": id2 + 9000}
            for id2 in (101, 102, 103)
        ]
        native = {
            "OBKNAJCIHEA": [{
                "LKBLPFHOAFB": {
                    "BBLLBIOLMHP": 1,
                    "JLFEAGHGCLP": {"BFLLDPOAJGD": square(0, 0, 10, 10)}
                },
                "OPHHFKKPLDI": [
                    child(101, square(2, 2, 4, 4)),
                    child(101, square(6, 6, 8, 8)),
                    child(102, square(20, 20, 30, 30)),
                ]
            }]
        }
        script = {"level1Areas": [
            {"level1Area": {"id1": 1}, "level2Areas": [{"id1": 1, "id2": 101}]}
        ]}
        result = world.analyze(config, native, script)
        self.assertEqual(3, result["configured_level2_ids"])
        self.assertEqual(3, result["level2_geometry_polygons"])
        self.assertEqual(2, result["distinct_level2_geometry_ids"])
        self.assertEqual({"101": 2}, result["duplicate_area_ids"])
        self.assertEqual([103], [
            row["areaID2"] for row in result["no_geometry_in_current_binary_source"]
        ])
        self.assertEqual([102], [
            row["areaID2"] for row in result["child_centroid_outside_declared_parent"]
        ])
        self.assertEqual(0, result["child_centroid_outside_declared_parent"][0]
                         ["child_vertices_inside_parent"])
        self.assertEqual([], result["missing_ids_found_in_script"])
        self.assertEqual([], result["parent_match_conflicts"])

    def test_concave_centroid_outside_self_is_not_false_parent_warning(self):
        # Concave L polygon centroid is outside the L itself.
        concave = [
            {"_x": 20, "_z": 20}, {"_x": 40, "_z": 20},
            {"_x": 40, "_z": 23}, {"_x": 23, "_z": 23},
            {"_x": 23, "_z": 40}, {"_x": 20, "_z": 40}
        ]
        native = {"OBKNAJCIHEA": [{
            "LKBLPFHOAFB": {
                "BBLLBIOLMHP": 1,
                "JLFEAGHGCLP": {"BFLLDPOAJGD": square(0, 0, 10, 10)}
            },
            "OPHHFKKPLDI": [child(101, concave)]
        }]}
        config = [{
            "sceneID": 3, "MBOHIOJBBHO": "LEVEL_2",
            "areaID1": 1, "areaID2": 101,
            "ID": 1101, "areaNameTextMapHash": 999
        }]
        self.assertFalse(world.contains(concave, 26.75, 26.75))
        self.assertEqual([], world.analyze(config, native)["child_centroid_outside_declared_parent"])

    def test_old_and_new_coordinate_field_names_normalize_without_geometry_loss(self):
        def polygon(kx, kz, ky):
            return {
                "BFLLDPOAJGD": [
                    {kx: 0.0, kz: 0.0}, {kx: 10.0, kz: 0.0},
                    {kx: 10.0, kz: 10.0}
                ],
                "MHLOLALFHHF": {ky: -1000.0},
                "NFFDCMLAAFO": {ky: 1000.0}
            }

        def resource(kx, kz, ky):
            return {"OBKNAJCIHEA": [{
                "LKBLPFHOAFB": {
                    "BBLLBIOLMHP": 1,
                    "JLFEAGHGCLP": polygon(kx, kz, ky)
                },
                "OPHHFKKPLDI": [{
                    "BBLLBIOLMHP": 1, "EOIFEEDBAFJ": 101,
                    "JLFEAGHGCLP": polygon(kx, kz, ky)
                }]
            }]}

        current = world.normalized_geometry(resource("_x", "_z", "_y"))
        older = world.normalized_geometry(resource("x", "z", "y"))
        self.assertEqual(current, older)
        self.assertEqual(2, sum(1 + len(v["level2"]) for v in current))
        older[0]["level2"][0]["geometry"]["maxY"] = 500
        self.assertNotEqual(current, older)

    def test_interior_grid_finds_a_crossing_even_when_centroid_is_inside(self):
        # The centroid (9, 3) is inside parent 1; x > 10 belongs to parent 2.
        native = {"OBKNAJCIHEA": [
            {"LKBLPFHOAFB": {
                "BBLLBIOLMHP": 1,
                "JLFEAGHGCLP": {"BFLLDPOAJGD": square(0, 0, 10, 10)}
             }, "OPHHFKKPLDI": [child(101, square(7, 2, 11, 4))]},
            {"LKBLPFHOAFB": {
                "BBLLBIOLMHP": 2,
                "JLFEAGHGCLP": {"BFLLDPOAJGD": square(10, 0, 20, 10)}
             }, "OPHHFKKPLDI": []},
        ]}
        config = [{
            "sceneID": 3, "MBOHIOJBBHO": "LEVEL_2", "areaID1": 1,
            "areaID2": 101, "ID": 1001, "areaNameTextMapHash": 999,
        }]
        result = world.analyze(config, native)
        self.assertEqual([], result["child_centroid_outside_declared_parent"])
        self.assertEqual(17, result["interior_grid_resolution"])
        crossing = result["child_interior_outside_declared_parent"]
        self.assertEqual([101], [row["areaID2"] for row in crossing])
        self.assertGreater(crossing[0]["inside_parent_samples"], 0)
        self.assertGreater(crossing[0]["outside_parent_samples"], 0)
        self.assertEqual([2], crossing[0]["witness"]["other_level1_ids"])
        self.assertFalse(crossing[0]["no_inside_parent_grid_samples"])

    def test_interior_grid_does_not_equate_no_witness_with_proven_containment(self):
        native = {"OBKNAJCIHEA": [{
            "LKBLPFHOAFB": {
                "BBLLBIOLMHP": 1,
                "JLFEAGHGCLP": {"BFLLDPOAJGD": square(0, 0, 10, 10)}
            },
            "OPHHFKKPLDI": [
                child(101, square(2, 2, 4, 4)),
                child(102, square(20, 20, 30, 30)),
            ],
        }]}
        config = [
            {"sceneID": 3, "MBOHIOJBBHO": "LEVEL_2",
             "areaID1": 1, "areaID2": id2,
             "ID": id2, "areaNameTextMapHash": id2 + 9000}
            for id2 in (101, 102)
        ]
        result = world.analyze(config, native)
        crossing = result["child_interior_outside_declared_parent"]
        self.assertEqual([102], [row["areaID2"] for row in crossing])
        self.assertTrue(crossing[0]["no_inside_parent_grid_samples"])
        self.assertEqual(289, crossing[0]["outside_parent_samples"])
        with self.assertRaises(ValueError):
            world.interior_grid_crossings([], [], resolution=0)

    def test_split_edge_detects_sliver_missed_by_fixed_grid(self):
        native = {"OBKNAJCIHEA": [{
            "LKBLPFHOAFB": {
                "BBLLBIOLMHP": 1,
                "JLFEAGHGCLP": {"BFLLDPOAJGD": square(-10, -10, 19.9, 20)}
            },
            "OPHHFKKPLDI": [child(101, square(0, 0, 20, 10))],
        }]}
        config = [{
            "sceneID": 3, "MBOHIOJBBHO": "LEVEL_2",
            "areaID1": 1, "areaID2": 101,
            "ID": 1001, "areaNameTextMapHash": 999,
        }]
        report = world.analyze(config, native)
        self.assertEqual([], report["child_interior_outside_declared_parent"])
        # An explicit small clearance makes the thin sliver a positive witness.
        parents, children = world.bin_polygons(native)
        hits = world.edge_interior_crossings(parents, children, clearance=0.001)
        self.assertEqual([101], [hit["areaID2"] for hit in hits])
        pt = hits[0]["witness"]
        self.assertTrue(world.contains(children[0]["points"], pt["x"], pt["z"]))
        self.assertFalse(world.contains(children[0]["parent_points"], pt["x"], pt["z"]))
        self.assertGreater(pt["margin"], 0.001)
        self.assertEqual([], world.edge_interior_crossings(parents, children, clearance=10))
        with self.assertRaises(ValueError):
            world.edge_interior_crossings(parents, children, clearance=-1)

    def test_edge_crossings_report_interior_margin_for_disjoint_child(self):
        native = {"OBKNAJCIHEA": [{
            "LKBLPFHOAFB": {
                "BBLLBIOLMHP": 1,
                "JLFEAGHGCLP": {"BFLLDPOAJGD": square(0, 0, 10, 10)}
            },
            "OPHHFKKPLDI": [child(101, square(20, 20, 30, 30))],
        }]}
        parents, children = world.bin_polygons(native)
        hits = world.edge_interior_crossings(parents, children)
        self.assertEqual([101], [v["areaID2"] for v in hits])
        self.assertGreaterEqual(hits[0]["witness"]["margin"], world.EDGE_CLEARANCE)

    def test_source_blob_is_byte_sensitive(self):
        self.assertEqual("3b18e512dba79e4c8300dd08aeb37f8e728b8dad",
                         world.blob_sha(b"hello world\n"))
        self.assertNotEqual(world.blob_sha(b"{}"), world.blob_sha(b"{}\n"))


if __name__ == "__main__":
    unittest.main()
