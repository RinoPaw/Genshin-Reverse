"""Synthetic tests for original Global 7.1 chest audio/handbook path hashes."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

from genshinre.assetindex import (
    AssetBlockRef, AssetIndex, AssetNameHash, mihoyo_name_hash,
)

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "chest_lv3_native_index", ROOT / "scripts/probe-7.1-chest-lv3-native-index.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def fixture(*, resolved=()):
    paths = [probe.CONTROL, *(probe.PATHS[key] for key in resolved)]
    entries = []
    for i, path in enumerate(paths, start=1):
        digest = mihoyo_name_hash(path)
        entries.append((AssetNameHash(digest & 255, digest >> 8, i),
                        AssetBlockRef(i, 25539185, 0, 0)))
    return AssetIndex(tuple(x for x, _ in entries),
                      {25539185: 0}, tuple(x for _, x in entries), ())


class ChestLv3OriginalIndexTests(unittest.TestCase):
    def test_source_hashes_are_exact_and_distinct(self):
        self.assertEqual(f"0x{mihoyo_name_hash(probe.PATHS['audioChestType']):010X}",
                         "0x5560E262E3")
        self.assertEqual(f"0x{mihoyo_name_hash(probe.PATHS['handbookOpenChest']):010X}",
                         "0x20C111A6D7")
        self.assertEqual(len(set(probe.EXPECTED_HASHES.values())), 2)

    def test_two_hits_stay_non_authoritative(self):
        result = probe.audit(fixture(resolved=("audioChestType", "handbookOpenChest")),
                             sha256=probe.INDEX_SHA256)
        self.assertEqual(result["candidateStatusCounts"], {"HASH_RESOLVED": 2})
        self.assertEqual(result["candidates"]["audioChestType"]
                         ["indexResult"]["blockId"], 25539185)
        self.assertTrue(any("payout" in line for line in result["limitations"]))

    def test_missing_names_do_not_imply_missing_server_logic(self):
        result = probe.audit(fixture(), sha256=probe.INDEX_SHA256)
        self.assertEqual(result["candidateStatusCounts"], {"HASH_ABSENT": 2})
        self.assertEqual(result["candidates"]["handbookOpenChest"]
                         ["indexResult"]["nameMatchCount"], 0)
        self.assertEqual(result["status"],
                         "EXACT_7_1_GLOBAL_DESIGN_INDEX_PATH_PROBE__ROW_SEMANTICS_UNVERIFIED")

    def test_fail_closed_wrong_source_and_control(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            probe.run(b"not an original 7.1 raw index")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            probe.audit(fixture(), sha256="wrong")
        bad = AssetIndex((), {}, (), ())
        with self.assertRaisesRegex(ValueError, "Gadget original index control"):
            probe.audit(bad, sha256=probe.INDEX_SHA256)


if __name__ == "__main__":
    unittest.main()
