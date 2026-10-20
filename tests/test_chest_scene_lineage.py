"""Synthetic tests for chest scene source continuity auditor."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1]/"scripts/audit-chest-scene-lineage.py"
spec = importlib.util.spec_from_file_location("chest_scene_lineage", SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
A, B, C, D = ("a"*40, "b"*40, "c"*40, "d"*40)

def tree(sha, paths, truncated=False):
    return {"sha": sha, "truncated": truncated,
            "tree": [{"type": "blob", "path": name, "sha": value} for name, value in paths]}

class ChestSceneLineageTest(unittest.TestCase):
    def test_continuity_and_changed_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/"tree.json"
            path.write_text(json.dumps(tree(A, [("scene3_group1.lua", B),
                ("scene3_group2.lua", C), ("scene3.lua", B), ("scene1_group3.lua", B)])))
            early = audit.load_tree(path, A)
            path.write_text(json.dumps(tree(D, [("scene3_group1.lua", B),
                ("scene3_group2.lua", D), ("scene3_group3.lua", B), ("scene3.lua", B)])))
            later = audit.load_tree(path, D)
            result = audit.compare(early, later, 3, "scene3_group1.lua")
            self.assertEqual({"shared": 2, "identical": 1, "different": 1}, result["groupFiles"])
            self.assertEqual(1, result["allFiles"]["earlierOnly"])
            self.assertEqual(1, result["allFiles"]["laterOnly"])
            self.assertTrue(result["sample"]["identical"])
            self.assertFalse(result["clientNative71Verified"])
            with self.assertRaises(ValueError):
                audit.compare(early, later, 3, "missing.lua")

    def test_reject_incomplete_and_ambiguous(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/"tree.json"
            bads = [tree(A, [], truncated=True), tree(A, [("same", B), ("same", C)]),
                    tree(A, [("nested/f.lua", B)]), tree(A, [("x.lua", "bad")])]
            for obj in bads:
                path.write_text(json.dumps(obj))
                with self.assertRaises(ValueError):
                    audit.load_tree(path, A)
            path.write_text(json.dumps(tree(A, [])))
            with self.assertRaises(ValueError):
                audit.load_tree(path, B)

if __name__ == "__main__":
    unittest.main()
