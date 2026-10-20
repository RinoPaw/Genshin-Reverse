"""Synthetic tests for the 7.1 chest asset path-hash probe."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

from genshinre.assetindex import AssetIndex, AssetNameHash, AssetBlockRef, mihoyo_name_hash

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/probe-7.1-chest-native-assets.py"
spec = importlib.util.spec_from_file_location("chest_native_probe_71", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def record(path: str, asset_id: int, block_id: int):
    value = mihoyo_name_hash(path)
    return (AssetNameHash(value & 255, value >> 8, asset_id),
            AssetBlockRef(asset_id, block_id, 0, 0))


class TestNativeChestAssetProbe(unittest.TestCase):
    def test_controls_and_candidate_scope(self):
        targets = [(path, i + 1, 25539185)
                   for i, path in enumerate(probe.CONTROL_PATHS)]
        targets.append((probe.CANDIDATES["gadget-identity"][0], 50, 24230448))
        rows = [record(*item) for item in targets]
        index = AssetIndex(tuple(name for name, _ in rows),
                           {25539185: 0, 24230448: 0},
                           tuple(ref for _, ref in rows), ())
        report = probe.audit(index, index_sha256=probe.INDEX_SHA256)
        self.assertEqual(report["status"], "EXACT_7_1_DESIGN_INDEX_PATH_HASH_PROBE_ONLY")
        self.assertEqual(report["groups"]["gadget-identity"][0]["status"], "HASH_RESOLVED")
        self.assertEqual(report["groups"]["gadget-identity"][1]["status"], "HASH_ABSENT")
        self.assertEqual(report["candidateStatusCounts"]["HASH_RESOLVED"], 1)
        self.assertNotIn("chestGrade", report)

    def test_missing_or_broken_controls_rejected(self):
        with self.assertRaisesRegex(ValueError, "control lookup failed"):
            probe.audit(AssetIndex((), {}, (), ()), index_sha256="test")
        rows = [record(path, i + 1, 12345)
                for i, path in enumerate(probe.CONTROL_PATHS)]
        index = AssetIndex(tuple(name for name, _ in rows),
                           {12345: 0}, tuple(ref for _, ref in rows), ())
        with self.assertRaisesRegex(ValueError, "control lookup failed"):
            probe.audit(index, index_sha256="test")

    def test_input_hash_is_checked_before_parsing(self):
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            probe.run(b"not the 7.1 design index")


if __name__ == "__main__":
    unittest.main()
