"""Synthetic geometry tests; no proprietary mesh bytes enter the repository."""
import unittest

from genshinre.worldmesh import IDENTITY, WorldMesh


class WorldMeshTests(unittest.TestCase):
    def test_upward_triangle_and_ray_limit(self):
        mesh = WorldMesh.from_obj(
            "v 0 2 0\nv 0 2 1\nv 1 2 0\nf 1 2 3\n"
        )
        self.assertEqual((2.0, 2.0), (mesh.bounds()[0][1], mesh.bounds()[1][1]))
        self.assertAlmostEqual(2, mesh.raycast_down(.25, .25))
        self.assertIsNone(mesh.raycast_down(.8, .8))
        self.assertIsNone(mesh.raycast_down(.25, .25, start_y=1))
        self.assertEqual(16, len(IDENTITY))

    def test_verified_matrix_translation_and_backface(self):
        mesh = WorldMesh.from_obj(
            "v 0 2 0\nv 0 2 1\nv 1 2 0\nf 1 2 3"
        )
        transform = (
            1.,0.,0.,10.,
            0.,1.,0.,5.,
            0.,0.,1.,20.,
            0.,0.,0.,1.,
        )
        self.assertAlmostEqual(7, mesh.raycast_down(10.25, 20.25,
                                                  world_from_local=transform))
        reversed_mesh = WorldMesh.from_obj(
            "v 0 2 0\nv 0 2 1\nv 1 2 0\nf 1 3 2"
        )
        self.assertIsNone(reversed_mesh.raycast_down(.25, .25))

    def test_obj_quad_negative_indices_and_errors(self):
        square = WorldMesh.from_obj(
            "v 0 1 0\nv 0 1 1\nv 1 1 1\nv 1 1 0\nf -4 -3 -2 -1"
        )
        self.assertEqual(2, len(square.triangles))
        self.assertAlmostEqual(1, square.raycast_down(.5, .5))
        for invalid in (
            "v 0 0 0\nv 1 0 0\nf 1 2 3",
            "v NaN 0 0\nv 0 1 0\nv 1 0 0\nf 1 2 3",
            "v 0 0 0\nv 1 0 0\nv 0 1 0\nf 0 2 3",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    WorldMesh.from_obj(invalid)


if __name__ == "__main__":
    unittest.main()
