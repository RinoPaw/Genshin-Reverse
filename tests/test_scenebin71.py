"""Regression tests for source-pinned native Global 7.1 Scene table counts."""
from __future__ import annotations

import hashlib
import struct
import unittest
from unittest.mock import patch

from genshinre import scenebin71

class TestSceneBin71NativeHeaders(unittest.TestCase):
    def test_native_7_1_header_operations_and_exact_method_pins(self):
        tag = scenebin71.SOURCES["SceneTagConfigData"]
        scene = scenebin71.SOURCES["SceneExcelConfigData"]
        self.assertEqual(tag["loader_rva"], 0x14015460)
        self.assertEqual(scene["loader_rva"], 0xA6C7000)
        self.assertEqual(tag["method_index"], 696653)
        self.assertEqual(scene["method_index"], 279989)
        self.assertEqual(tag["key_offset"], 0x28)
        self.assertEqual(scene["key_offset"], 0x50)
        self.assertEqual((0xF16A9948 ^ tag["immediate"]), 1147)
        self.assertEqual((0x474DEA8D + scene["immediate"]) & 0xFFFFFFFF, 2377)

    def test_synthetic_pinned_files_decode_both_and_preserve_scope(self):
        for source in scenebin71.SOURCES:
            record = dict(scenebin71.SOURCES[source])
            count = record["count"]
            header = (count ^ record["immediate"]) if record["op"] == "xor" else (
                count - record["immediate"]) & 0xFFFFFFFF
            body = struct.pack("<I", header) + b"fake-row-wire"
            raw = struct.pack("<I", len(body)) + body + b"\0\0\0"
            record["raw_sha"] = hashlib.sha256(raw).hexdigest()
            record["payload_sha"] = hashlib.sha256(body).hexdigest()
            with self.subTest(source=source), patch.dict(scenebin71.SOURCES, {source: record}):
                result = scenebin71.decode_source_header(raw, source=source)
                self.assertEqual(result.row_count, count)
                self.assertEqual(result.payload_bytes, len(body))
                self.assertFalse(result.summary()["rowSchemaDecoded"])
                self.assertFalse(result.summary()["serverDropTagProven"])
                with self.assertRaisesRegex(scenebin71.SceneBin71Error, "raw export SHA-256"):
                    scenebin71.decode_source_header(raw[:-1]+b"x", source=source)

    def test_unknown_file_fails_closed(self):
        with self.assertRaisesRegex(scenebin71.SceneBin71Error, "unknown pinned"):
            scenebin71.decode_source_header(b"", source="SceneDropTagServerConfigData")
        with self.assertRaisesRegex(scenebin71.SceneBin71Error, "raw export SHA-256"):
            scenebin71.decode_source_header(b"abcd", source="SceneTagConfigData")


if __name__ == "__main__":
    unittest.main()
