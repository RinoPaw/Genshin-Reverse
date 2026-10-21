"""Original Global 7.1 SceneTag/SceneExcel metadata neighbor provenance."""
from __future__ import annotations

import csv
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/probe-7.1-scene-neighbor-types.py"
spec = importlib.util.spec_from_file_location("scene_neighbor_71", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def write_csv(path, columns, records):
    with path.open("w", encoding="utf-8", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=columns)
        writer.writeheader()
        writer.writerows(records)


class TestSceneNeighborTypes71(unittest.TestCase):
    def test_original_loader_type_anchors(self):
        self.assertEqual(probe.MANAGERS["SceneTag"]["index"], 84296)
        self.assertEqual(probe.MANAGERS["SceneExcel"]["index"], 35441)
        self.assertEqual(probe.MANAGERS["SceneTag"]["type"], "EJCNENCJADF")
        self.assertEqual(probe.MANAGERS["SceneExcel"]["type"], "HPNMCGDJOJL")

    def test_nearby_method_with_shared_signature_does_not_become_reader(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            t, m, f = (root/"types.csv", root/"methods.csv", root/"fields.csv")
            write_csv(t, ["type_definition_index", "type_name", "parent_type",
                          "field_count", "method_count", "field_start", "method_start"], [
                {"type_definition_index": 84296, "type_name": "EJCNENCJADF",
                 "field_count": 2, "method_count": 6, "field_start": 100, "method_start": 1000},
                {"type_definition_index": 84297, "type_name": "SOME_NEIGHBOR",
                 "field_count": 5, "method_count": 3, "field_start": 102, "method_start": 1006},
                {"type_definition_index": 35441, "type_name": "HPNMCGDJOJL",
                 "field_count": 2, "method_count": 6, "field_start": 200, "method_start": 2000},
            ])
            write_csv(m, ["type_definition_index", "method_index", "method_name",
                          "rva", "parameter_types", "parameter_count"], [
                {"type_definition_index": 84297, "method_index": 1006,
                 "method_name": "GMENPOPMKAA", "rva": "0x123456",
                 "parameter_types": '["FNIAHJGHFAK"]', "parameter_count": 1},
            ])
            write_csv(f, ["type_definition_index", "field_name", "field_type", "offset"], [
                {"type_definition_index": 84297, "field_name": "FIELD",
                 "field_type": "uint32", "offset": ""},
            ])
            result = probe.inspect(t, m, f, radius=2)
            tag = result["tables"]["SceneTag"]
            self.assertEqual(tag["typesObserved"], 2)
            self.assertEqual(len(tag["sameMethodAndInputSignatureCandidates"]), 1)
            self.assertEqual(tag["sameMethodAndInputSignatureCandidates"][0]
                             ["distanceFromManagerType"], 1)
            self.assertEqual(result["tables"]["SceneExcel"]
                             ["sameMethodAndInputSignatureCandidates"], [])
            self.assertIn("UNVERIFIED", result["status"])
            self.assertFalse(any("proven" in k.lower() for k in tag))
            with self.assertRaisesRegex(ValueError, "bounded"):
                probe.inspect(t, m, f, radius=100)
            with self.assertRaisesRegex(ValueError, "bounded"):
                probe.inspect(t, m, f, radius=0)

    def test_manager_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            t, m, f = (root/"t", root/"m", root/"f")
            write_csv(t, ["type_definition_index", "type_name"], [])
            with self.assertRaisesRegex(ValueError, "original type identity"):
                probe.inspect(t, m, f)


if __name__ == "__main__":
    unittest.main()
