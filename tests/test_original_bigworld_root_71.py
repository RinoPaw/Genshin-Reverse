"""Regression checks for the pinned original Global 7.1 BigWorld sector snapshot."""
import hashlib
import json
from pathlib import Path
import unittest


class NativeBigWorldRootTests(unittest.TestCase):
    def test_original_sector_list_and_name_control(self):
        source = (Path(__file__).resolve().parents[1] /
                  "versions/7.1.0-global/analyses/world/7.1-original-bigworld-sector-root.json")
        record = json.loads(source.read_text(encoding="utf-8"))
        root = record["root"]
        names = root["sectorNames"]
        self.assertEqual("BigWorld", root["worldName"])
        self.assertEqual("BigWorldConfig", root["configName"])
        self.assertEqual(1292, root["sectorCount"])
        self.assertEqual(len(names),len(set(names)))
        self.assertEqual(358,root["numericGridSectorCount"])
        self.assertEqual(358, sum(n.startswith("BigWorld_") for n in names))
        self.assertEqual(584, sum(n.startswith("Area_") for n in names))
        self.assertIn("BigWorld_-1_14", names)
        self.assertEqual(
            root["sectorNamesSha256"],
            hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest()
        )
        self.assertEqual(
            ["BigWorld_-1_14_TerrainMesh_JJH_ERR_59_Lod1",
             "BigWorld_-1_14_TerrainMesh_JJH_ERR_59_Lod2"],
            record["meshNameControl"]["originalTerrainMeshNames"],
        )
        self.assertEqual(
            "LEXICAL_NAME_CORRESPONDENCE_ONLY",
            record["meshNameControl"]["status"],
        )
        self.assertFalse(record["limits"]["serverWorldRaycastReady"])
        self.assertEqual("UNRESOLVED", record["limits"]["terrainWorldPlacement"])


if __name__ == "__main__":
    unittest.main()
