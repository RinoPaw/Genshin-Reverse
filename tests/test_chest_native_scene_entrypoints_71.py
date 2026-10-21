"""Scene Excel / SceneTag exact-source controls without including game bytes."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from genshinre.assetindex import AssetIndex, AssetNameHash, AssetBlockRef, mihoyo_name_hash

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/audit-7.1-native-scene-entrypoints.py"
spec = importlib.util.spec_from_file_location("native_scene_entries_71", SCRIPT)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


def fake_index():
    names = []
    refs = []
    for i, path in enumerate((tool.CONTROL, *tool.REQUIRED), 1):
        h = mihoyo_name_hash(path)
        names.append(AssetNameHash(h & 0xff, h >> 8, i))
        refs.append(AssetBlockRef(i, tool.BLOCK[1], 0, 0))
    return AssetIndex(tuple(names), {tool.BLOCK[1]: 0}, tuple(refs), ())


class TestExactNativeSceneEntrypoints71(unittest.TestCase):
    def test_authenticated_export_and_field_scope(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "MiHoYoBinData"
            root.mkdir()
            fixture = {tool.CONTROL: b"control", tool.REQUIRED[0]: b"\x01\x02\xff\x00",
                       tool.REQUIRED[1]: b"\x08\x09hello"}
            for path, payload in fixture.items():
                h = mihoyo_name_hash(path) >> 8
                (root / f"{h:08x}.dat").write_bytes(
                    struct.pack("<I", len(payload)) + payload)
            known = hashlib.sha256(
                struct.pack("<I", len(fixture[tool.CONTROL])) +
                fixture[tool.CONTROL]).hexdigest()
            with patch.object(tool, "CONTROL_GADGET_RAW_SHA256", known):
                r = tool.inspect(fake_index(), root.parent)
            self.assertEqual(len(r["assets"]), 2)
            self.assertEqual(r["assets"][0]["payloadBytes"], 4)
            self.assertEqual(r["assets"][0]["payloadFirst32Hex"], "0102ff00")
            self.assertFalse(r["assets"][0]["wholePayloadUtf8"])
            self.assertTrue(r["assets"][1]["wholePayloadUtf8"])
            self.assertIn("FIELD_MEANING_UNKNOWN", r["status"])
            self.assertTrue(any("drop_tag" in x for x in r["limitations"]))

    def test_source_gate_and_gadget_control_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "design index SHA-256"):
            tool.audit(b"not the exact original index", Path("/none"))
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "MiHoYoBinData"
            root.mkdir()
            path = tool.CONTROL
            (root / f"{mihoyo_name_hash(path) >> 8:08x}.dat").write_bytes(b"fake")
            with self.assertRaisesRegex(ValueError, "Gadget control"):
                tool.inspect(fake_index(), root.parent)

    def test_broken_original_entrypoint_fails(self):
        with self.assertRaisesRegex(ValueError, "source identity"):
            tool.inspect(AssetIndex((), {}, (), ()), Path("/none"))


if __name__ == "__main__":
    unittest.main()
