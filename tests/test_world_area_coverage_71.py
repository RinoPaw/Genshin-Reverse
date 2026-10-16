import importlib.util
import json
from pathlib import Path
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "scripts/audit-7.1-world-area-coverage.py"
spec = importlib.util.spec_from_file_location("world_area_coverage_71", SOURCE)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class WorldAreaCoverageTest(unittest.TestCase):
    def test_hash_named_source_maps_by_parent_ids_not_filename(self):
        config = [
            {"sceneID": 3, "MBOHIOJBBHO": "LEVEL_1", "areaID1": 1},
            {"sceneID": 3, "MBOHIOJBBHO": "LEVEL_2",
             "areaID1": 1, "areaID2": 101, "ID": 10},
            {"sceneID": 101, "MBOHIOJBBHO": "LEVEL_1", "areaID1": 800},
            {"sceneID": 101, "MBOHIOJBBHO": "LEVEL_2",
             "areaID1": 800, "areaID2": 80011, "ID": 123},
        ]
        geometry = {
            "scene3_worldArea.json": {
                "OBKNAJCIHEA": [{
                    "LKBLPFHOAFB": {"BBLLBIOLMHP": 1},
                    "OPHHFKKPLDI": [{
                        "BBLLBIOLMHP": 1, "EOIFEEDBAFJ": 101,
                    }],
                }],
            },
            "8a14d94c.json": {
                "OBKNAJCIHEA": [{
                    "LKBLPFHOAFB": {"BBLLBIOLMHP": 800},
                    "OPHHFKKPLDI": [],
                }],
            },
        }
        result = audit.collect(config, geometry)
        self.assertEqual(2, result["scene_count"])
        self.assertEqual(2, result["configured_level2"])
        self.assertEqual(1, result["distinct_level2_polygons"])
        self.assertEqual([{"sceneID": 101, "areaID1": 800,
                           "areaID2": 80011, "configID": 123}],
                         result["missing_level2_geometry"])
        self.assertEqual("8a14d94c.json", result["scenes"][1]["geometry_file"])

    def test_committed_coverage_observations_are_consistent(self):
        report_path = (SOURCE.parents[1] /
                       "versions/7.1.0-global/analyses/progression/world/" /
                       "7.1-all-world-area-scene-coverage.json")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(13, report["scene_count"])
        self.assertTrue(report["historical_comparison"]["all_files_identical"])
        self.assertEqual(9167, report["historical_comparison"]["total_vertices"])
        self.assertEqual(90, report["configured_level1"])
        self.assertEqual(488, report["configured_level2"])
        self.assertEqual(480, report["level2_polygon_records"])
        self.assertEqual(474, report["distinct_level2_polygons"])
        crossings = report.get("cross_scene_parent_gate_geometry")
        self.assertIsNotNone(crossings)
        self.assertEqual(24, crossings["total_positive_child_polygon_records"])
        self.assertEqual([(7, 21001)], [
            (row["sceneID"], row["areaID2"])
            for row in crossings["interior_witnesses"] if row["sceneID"] != 3
        ])
        expected = audit.EXPECTED_MISSING
        self.assertEqual(expected, {
            (row["sceneID"], row["areaID2"])
            for row in report["missing_level2_geometry"]
        })
        self.assertEqual(set(audit.GEOMETRY_BLOBS),
                         set(report["source_pins"]["geometry_blobs"]))
        for row in report["scenes"]:
            self.assertFalse(row["extra_level2_geometry"])
            self.assertFalse(row["parent_id_mismatch"])

    def test_7_0_coordinate_spelling_normalizes_without_dropping_y(self):
        def one(xkey, zkey, ykey):
            return {"OBKNAJCIHEA": [{
                "LKBLPFHOAFB": {
                    "BBLLBIOLMHP": 800,
                    "JLFEAGHGCLP": {
                        "BFLLDPOAJGD": [
                            {xkey: 1, zkey: 2, ykey: 3},
                            {xkey: 4, zkey: 5, ykey: 6},
                        ],
                        "MHLOLALFHHF": {ykey: -100},
                        "NFFDCMLAAFO": {ykey: 200},
                    },
                },
                "OPHHFKKPLDI": [{
                    "BBLLBIOLMHP": 800, "EOIFEEDBAFJ": 80001,
                    "JLFEAGHGCLP": {
                        "BFLLDPOAJGD": [
                            {xkey: 7, zkey: 8},
                            {xkey: 9, zkey: 10},
                        ]
                    },
                }],
            }]}
        old = {"8a14d94c.json": one("x", "z", "y")}
        now = {"8a14d94c.json": one("_x", "_z", "_y")}
        report = audit.compare_historic(now, old)
        self.assertTrue(report["all_files_identical"])
        self.assertEqual(4, report["total_vertices"])
        old["8a14d94c.json"]["OBKNAJCIHEA"][0]["LKBLPFHOAFB"][
            "JLFEAGHGCLP"]["BFLLDPOAJGD"][0]["y"] = 99
        self.assertFalse(audit.compare_historic(now, old)["all_files_identical"])
        with self.assertRaisesRegex(ValueError, "file set"):
            audit.compare_historic({}, old)

    def test_native_order_model_parent_first_and_child_height_inclusive(self):
        world_path = SOURCE.with_name("audit-7.1-world-areas.py")
        spec = importlib.util.spec_from_file_location("world_area_scene3_model_71", world_path)
        world = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(world)

        def rectangle(x0, z0, x1, z1):
            return [
                {"_x": x0, "_z": z0}, {"_x": x1, "_z": z0},
                {"_x": x1, "_z": z1}, {"_x": x0, "_z": z1},
            ]

        def shape(points, min_y=None, max_y=None):
            obj = {"BFLLDPOAJGD": points}
            if min_y is not None:
                obj["MHLOLALFHHF"] = {"_y": min_y}
            if max_y is not None:
                obj["NFFDCMLAAFO"] = {"_y": max_y}
            return {"JLFEAGHGCLP": obj}

        data = {"OBKNAJCIHEA": [
            {
                "LKBLPFHOAFB": {
                    "BBLLBIOLMHP": 1,
                    **shape(rectangle(0, 0, 10, 10)),
                },
                "OPHHFKKPLDI": [
                    {"BBLLBIOLMHP": 1, "EOIFEEDBAFJ": 101,
                     **shape(rectangle(8, 2, 12, 8), 0, 10)},
                    {"BBLLBIOLMHP": 1, "EOIFEEDBAFJ": 102,
                     **shape(rectangle(2, 2, 4, 8), 0, None)},
                ],
            },
            {
                "LKBLPFHOAFB": {
                    "BBLLBIOLMHP": 2,
                    **shape(rectangle(6, 0, 16, 10)),
                },
                "OPHHFKKPLDI": [
                    {"BBLLBIOLMHP": 2, "EOIFEEDBAFJ": 201,
                     **shape(rectangle(6, 2, 9, 8), 0, 10)},
                ],
            },
        ]}
        model = lambda x, y, z: audit.predict_native_ordered_area_from_dump(
            data, x, y, z, world
        )
        # The child upper Y bound is inclusive in the native spatial predicate.
        self.assertEqual(
            {"status": "CHILD_MATCH", "areaID1": 1, "areaID2": 101},
            model(9, 10, 5),
        )
        self.assertEqual(
            {"status": "PARENT_ONLY", "areaID1": 1},
            model(9, 11, 5),
        )
        # Parent 1 wins even where parent 2 also contains a matching child.
        self.assertEqual(
            {"status": "PARENT_ONLY", "areaID1": 1},
            model(7, 5, 5),
        )
        # Child 101 extends outside parent 1; it cannot win at x=11.
        self.assertEqual(
            {"status": "PARENT_ONLY", "areaID1": 2},
            model(11, 5, 5),
        )
        self.assertEqual(
            {"status": "UNKNOWN_CHILD_HEIGHT", "areaID1": 1,
             "candidate_areaID2": 102},
            model(3, 5, 5),
        )
        self.assertEqual({"status": "NO_PARENT"}, model(20, 5, 5))

    def test_across_scenes_parent_gated_edge_witnesses(self):
        world_path = SOURCE.with_name("audit-7.1-world-areas.py")
        spec = importlib.util.spec_from_file_location("world_area_scene3_71", world_path)
        world = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(world)
        def poly(x0, z0, x1, z1):
            return [{"_x": x0, "_z": z0}, {"_x": x1, "_z": z0},
                    {"_x": x1, "_z": z1}, {"_x": x0, "_z": z1}]
        def shaped(points):
            return {"JLFEAGHGCLP": {"BFLLDPOAJGD": points}}
        geom = {
            "scene7_worldArea.json": {
                "OBKNAJCIHEA": [{
                    "LKBLPFHOAFB": {
                        "BBLLBIOLMHP": 210,
                        **shaped(poly(0, 0, 10, 10)),
                    },
                    "OPHHFKKPLDI": [{
                        "BBLLBIOLMHP": 210, "EOIFEEDBAFJ": 21001,
                        **shaped(poly(8, 2, 12, 8)),
                    }],
                }],
            },
            "scene4_worldArea.json": {
                "OBKNAJCIHEA": [{
                    "LKBLPFHOAFB": {
                        "BBLLBIOLMHP": 100,
                        **shaped(poly(0, 0, 10, 10)),
                    },
                    "OPHHFKKPLDI": [{
                        "BBLLBIOLMHP": 100, "EOIFEEDBAFJ": 10001,
                        **shaped(poly(2, 2, 8, 8)),
                    }],
                }],
            },
        }
        report = {
            "scenes": [
                {"sceneID": 4, "geometry_file": "scene4_worldArea.json"},
                {"sceneID": 7, "geometry_file": "scene7_worldArea.json"},
            ],
        }
        scanned = audit.scan_parent_gated_disagreements(report, geom, world)
        self.assertEqual(1, scanned["total_positive_child_polygon_records"])
        self.assertEqual(
            [{"sceneID": 7, "areaID2": 21001}], scanned["positive_child_ids"]
        )
        witness = scanned["interior_witnesses"][0]
        self.assertEqual(210, witness["areaID1"])
        self.assertGreater(witness["witness"]["margin"], 0.25)
        self.assertEqual([0, 1], [
            row["positive_child_polygon_records"]
            for row in scanned["by_scene"]
        ])

    def test_ambiguous_scene_or_missing_file_fails_closed(self):
        config = [
            {"sceneID": 101, "MBOHIOJBBHO": "LEVEL_1", "areaID1": 800},
            {"sceneID": 102, "MBOHIOJBBHO": "LEVEL_1", "areaID1": 800},
        ]
        geom = {"abc.json": {"OBKNAJCIHEA": [{
            "LKBLPFHOAFB": {"BBLLBIOLMHP": 800},
        }]}}
        with self.assertRaisesRegex(ValueError, "exactly one scene"):
            audit.collect(config, geom)

        with self.assertRaisesRegex(ValueError, "unmatched scene"):
            audit.collect(config[:1], {})

    def test_repeated_polygons_are_not_missing_ids(self):
        config = [
            {"sceneID": 3, "MBOHIOJBBHO": "LEVEL_1", "areaID1": 1},
            {"sceneID": 3, "MBOHIOJBBHO": "LEVEL_2",
             "areaID1": 1, "areaID2": 101, "ID": 42},
        ]
        child = {"BBLLBIOLMHP": 1, "EOIFEEDBAFJ": 101}
        geom = {"scene3_worldArea.json": {"OBKNAJCIHEA": [{
            "LKBLPFHOAFB": {"BBLLBIOLMHP": 1},
            "OPHHFKKPLDI": [child, child],
        }]}}
        result = audit.collect(config, geom)
        self.assertEqual(2, result["level2_polygon_records"])
        self.assertEqual(1, result["distinct_level2_polygons"])
        self.assertEqual([], result["missing_level2_geometry"])
        self.assertEqual({"101": 2}, result["scenes"][0]["repeated_level2_polygon_ids"])


if __name__ == "__main__":
    unittest.main()
