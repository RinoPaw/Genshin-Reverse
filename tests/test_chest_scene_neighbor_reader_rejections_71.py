"""Exact 7.1 negative source controls for two tempting metadata-adjacent readers."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

from genshinre.nativeprofile import PROFILE_71

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/audit-7.1-scene-neighbor-reader-rejections.py"
REPORT = (ROOT / "versions/7.1.0-global/analyses/progression/economy"
          / "7.1-chest-scene-adjacent-reader-rejections.json")
spec = importlib.util.spec_from_file_location("scene_negative_71", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def fake_native(name):
    spec = probe.SAMPLES[name]
    return {
        "exe_sha256": PROFILE_71.exe_sha256,
        "start_rva": spec["nativeRva"],
        "instructions": [
            {"rva": rva, "mnemonic": mnemonic, "op_str": operands}
            for rva, mnemonic, operands in spec["nativeAnchors"]
        ],
    }


def fake_original_shape(name):
    spec = probe.SAMPLES[name]
    # A made-up serialized prefix with the same byte-level first-record
    # obligations, but its SHA-256 must be temporarily injected.
    if name == "SceneTagConfigData":
        payload = (b"\x00" * 4 + struct.pack("<H", 0x440D)
                   + b"\x00" * 12 + struct.pack("<I", 0xB02416CC)
                   + b"\x00" * 40)
    else:
        payload = (b"\x00" * 4 + struct.pack("<I", 0x7565314C)
                   + b"\x00" * 4 + struct.pack("<I", 0x4E0467E4)
                   + b"\x00" * 40)
    raw = struct.pack("<I", len(payload)) + payload
    return raw, hashlib.sha256(raw).hexdigest(), hashlib.sha256(payload).hexdigest()


class TestSceneNeighborFirstRowRejections71(unittest.TestCase):
    def test_pinned_7_1_observation_is_only_negative_evidence(self):
        d = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertEqual(d["exeSha256"], PROFILE_71.exe_sha256)
        self.assertEqual(set(d["candidates"]), set(probe.SAMPLES))
        expected = {
            "SceneTagConfigData": (0x329B, 494924424, 38919),
            "SceneExcelConfigData": (0x7565314C, 4223952863, 273336),
        }
        for name, (mask, count, remaining) in expected.items():
            row = d["candidates"][name]
            self.assertEqual(row["rawExportSha256"], probe.SAMPLES[name]["rawSha256"])
            self.assertEqual(int(row["candidateDecodedMask"], 16), mask)
            self.assertEqual(row["candidateArrayLength"], count)
            self.assertEqual(row["remainingPayloadBytes"], remaining)
            self.assertEqual(row["candidateEntryOffsetAfterTableCount"], 4)
            self.assertEqual(row["nativeInstructionAnchorsMatched"],
                             len(probe.SAMPLES[name]["nativeAnchors"]))
            self.assertGreater(count, remaining)
        self.assertIn("ACTUAL_VTABLE_UNRESOLVED", d["status"])
        self.assertTrue(any("not a search" in x for x in d["limitations"]))

    def test_native_first_row_candidates_fail_original_stream_bounds(self):
        for name in probe.SAMPLES:
            raw, raw_sha, payload_sha = fake_original_shape(name)
            candidate = dict(probe.SAMPLES[name])
            candidate.update(rawSha256=raw_sha, payloadSha256=payload_sha)
            with self.subTest(name=name), patch.dict(probe.SAMPLES, {name:candidate}):
                result = probe.inspect_first_row(name, raw, fake_native(name))
                self.assertGreater(result["candidateArrayLength"],
                                   result["remainingPayloadBytes"])
                self.assertIn("INCONSISTENT", result["claim"])
                with self.assertRaisesRegex(ValueError, "raw original 7.1 SHA-256"):
                    probe.inspect_first_row(name, raw + b"x", fake_native(name))
                changed = copy.deepcopy(fake_native(name))
                changed["instructions"][0]["op_str"] = "eax, 0x0"
                with self.assertRaisesRegex(ValueError, "native instruction mismatch"):
                    probe.inspect_first_row(name, raw, changed)

    def test_method_lookalike_is_not_class_identity(self):
        self.assertNotEqual(probe.SAMPLES["SceneTagConfigData"]["methodIndex"], 696653)
        self.assertNotEqual(probe.SAMPLES["SceneExcelConfigData"]["methodIndex"], 279989)
        self.assertNotIn("sceneDropTag", probe.SAMPLES["SceneTagConfigData"])
        self.assertNotIn("chestRewardRoot", probe.SAMPLES["SceneExcelConfigData"])


if __name__ == "__main__":
    unittest.main()
