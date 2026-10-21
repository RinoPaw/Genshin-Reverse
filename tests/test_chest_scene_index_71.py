"""Synthetic exact-source boundary checks for original scene path probes."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

from genshinre.assetindex import AssetIndex, AssetNameHash, AssetBlockRef, mihoyo_name_hash

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/probe-7.1-chest-scene-index.py"
spec = importlib.util.spec_from_file_location("chest_scene_index_71", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def mock_index(extra=()):
    paths = [(p, probe.CONTROL_TARGETS[name][1])
             for name, p in probe.CONTROL.items()]
    paths += [(p, 24230448) for p in extra]
    names, refs = [], []
    for n, (path, block) in enumerate(paths, start=1):
        h = mihoyo_name_hash(path)
        names.append(AssetNameHash(h & 0xff, h >> 8, n))
        refs.append(AssetBlockRef(n, block, 0, 0))
    return AssetIndex(tuple(names),
                      {25539185: 0, 24230448: 0},
                      tuple(refs), ())


class TestExactChestSceneIndex71(unittest.TestCase):
    def test_positive_controls_bound_the_exact_asset_families(self):
        r = probe.analyze(mock_index(), digest=probe.INDEX_SHA256)
        self.assertEqual(r["source"]["designIndexNameCount"], 2)
        self.assertEqual(r["controls"]["known-Excel"]["blockId"], 25539185)
        self.assertEqual(r["controls"]["known-scene-area"]["blockId"], 24230448)
        self.assertEqual(r["candidateCount"], sum(
            group["hypothesesTested"] for group in r["groups"].values()))
        self.assertEqual(r["statusCounts"], {"HASH_ABSENT": r["candidateCount"]})
        self.assertNotIn("dropTag", r)
        self.assertNotIn("rewardRoot", r)
        self.assertEqual(r["source"]["indexType"], "MiHoYoBinData only")
        self.assertFalse(r["source"]["hypothesesAreSourcePaths"])

    def test_sample_group_hit_remains_hypothesis_only(self):
        candidate = ("Data/_BinOutput/Scene/3/"
                     "scene3_group133003154")
        self.assertIn(candidate, probe.candidates()["historical-group-name-hypotheses"])
        r = probe.analyze(mock_index((candidate,)), digest=probe.INDEX_SHA256)
        self.assertEqual(r["statusCounts"]["HASH_RESOLVED"], 1)
        hit = r["groups"]["historical-group-name-hypotheses"]["matchesOrAmbiguous"][0]
        self.assertEqual(hit["path"], candidate)
        self.assertEqual(hit["blockId"], 24230448)
        self.assertIn("UNRESOLVED", r["status"])

    def test_wrong_controls_rejected(self):
        with self.assertRaisesRegex(ValueError, "positive control failed"):
            probe.analyze(AssetIndex((), {}, (), ()), digest="synthetic")
        original = probe.CONTROL_TARGETS["known-scene-area"]
        probe.CONTROL_TARGETS["known-scene-area"] = (0, 99)
        try:
            with self.assertRaisesRegex(ValueError, "positive control failed"):
                probe.analyze(mock_index(), digest="synthetic")
        finally:
            probe.CONTROL_TARGETS["known-scene-area"] = original

    def test_source_gate_and_deterministic_candidates(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            probe.run(b"not pinned original 7.1")
        first, second = probe.candidates(), probe.candidates()
        self.assertEqual(first, second)
        all_names = [s for group in first.values() for s in group]
        self.assertEqual(len(set(all_names)), len(all_names))
        self.assertTrue(set(probe.CONTROL.values()).isdisjoint(all_names))
        self.assertTrue(any("Point" in p for p in first[
            "adjacent-scene-point-and-support-hypotheses"]))


if __name__ == "__main__":
    unittest.main()
