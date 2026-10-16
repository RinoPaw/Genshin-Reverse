from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "scripts/probe-7.1-world-area-assets.py"
spec = importlib.util.spec_from_file_location("probe_world_area_assets_71", SOURCE)
assets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assets)


class ExactWorldAreaAssetProbes(unittest.TestCase):
    def test_finite_deduplicated_original_path_hypotheses(self):
        candidates = assets.candidates()
        self.assertEqual(set(assets.SCENES), set(candidates))
        all_paths = [item for group in candidates.values() for item in group]
        self.assertEqual(len(all_paths), len(set(all_paths)))
        self.assertIn(
            "Data/_BinOutput/Scene/WorldArea/scene3_worldArea",
            candidates[3],
        )
        self.assertIn(
            "Data/_BinOutput/Scene/WorldArea/scene7_worldArea",
            candidates[7],
        )
        self.assertIn(
            "Data/_BinOutput/Scene/WorldArea/f0d16079",
            candidates[100],
        )

    def test_exact_official_index_hash_is_mandatory(self):
        with self.assertRaisesRegex(ValueError, "design-index export SHA256 mismatch"):
            assets.build_report(b"not a pinned index")

    def test_protocol_registry_is_not_confused_with_asset_index(self):
        self.assertTrue(all(x.startswith("Data/_ExcelBinOutput/") for x in
                            assets.CONTROL_PATHS))
        self.assertEqual(2, len(assets.CONTROL_PATHS))


if __name__ == "__main__":
    unittest.main()
