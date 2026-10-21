"""Synthetic tests for original Global 7.1 chest audio/handbook path hashes."""
from __future__ import annotations

import importlib.util
import hashlib
from pathlib import Path
import struct
import tempfile
from unittest import mock
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

    def test_source_block_export_fingerprint_is_nonsemantic(self):
        report = probe.audit(fixture(resolved=("audioChestType", "handbookOpenChest")),
                             sha256=probe.INDEX_SHA256)
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "MiHoYoBinData"
            directory.mkdir()
            gadget = b"native source control"
            (directory / probe.GADGET_EXPORT).write_bytes(gadget)
            sources = {
                "audioChestType": b"MidHiTop",
                "handbookOpenChest": b"open",
            }
            for key, payload in sources.items():
                name = report["candidates"][key]["indexResult"]["exportedName"] + ".dat"
                (directory / name).write_bytes(struct.pack("<I", len(payload)) + payload)
            with mock.patch.object(probe, "GADGET_RAW_SHA256",
                                   hashlib.sha256(gadget).hexdigest()):
                original = probe.inspect_original_export_dir(report, Path(temp))
                self.assertEqual(original["tables"]["audioChestType"]
                                 ["plainAsciiOccurrencesAreNotFieldProof"]["Mid"], 1)
                self.assertEqual(original["tables"]["handbookOpenChest"]
                                 ["payloadBytes"], 4)
                self.assertIn("ROW_SCHEMA_UNVERIFIED", original["status"])
                bad = report["candidates"]["audioChestType"]["indexResult"]["exportedName"]
                (directory / (bad + ".dat")).write_bytes(struct.pack("<I", 99) + b"x")
                with self.assertRaisesRegex(ValueError, "declares"):
                    probe.inspect_original_export_dir(report, Path(temp))
            with self.assertRaisesRegex(ValueError, "Gadget raw export control"):
                probe.inspect_original_export_dir(report, Path(temp))

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
