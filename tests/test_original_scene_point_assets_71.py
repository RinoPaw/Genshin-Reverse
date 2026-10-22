"""Source boundaries for Global 7.1 original Scene/Point asset source census."""
from __future__ import annotations

from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts/audit-7.1-original-scene-point-assets.py"
spec=importlib.util.spec_from_file_location("native_scene_point71",SCRIPT)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class SourceScenePointAudit(unittest.TestCase):
    def test_original_world_area_and_scene_point3_static_controls(self):
        self.assertEqual(m.SCENE_POINT3_HASH,"0xBC3AE3E1FD")
        self.assertEqual(len(m.SCENES),13)
        self.assertEqual(len(m.candidate_paths()),13)
        self.assertIn("scene3_point",m.candidate_paths()[0])
        self.assertEqual(m.WORLD_BLOCK,(0,24230448))

    def test_source_and_export_are_checked_before_semantics(self):
        class PseudoNames:
            def __len__(self):return 247073
            def __iter__(self):
                yield SimpleNamespace(exported_name="0c934d1c")
                yield SimpleNamespace(exported_name="bc3ae3e1")
        index=SimpleNamespace(names=PseudoNames())
        def query(index,paths):
            if paths==[m.WORLD_AREA3,m.SCENE_POINT3]:
                return [
                    {"status":"HASH_RESOLVED","groupId":0,"blockId":24230448,
                     "exportedName":"0c934d1c","pathHash":"0x0C934D1C2C"},
                    {"status":"HASH_RESOLVED","groupId":0,"blockId":24230448,
                     "exportedName":"bc3ae3e1","pathHash":m.SCENE_POINT3_HASH}
                ]
            out=[]
            for p in paths:
                if p.endswith("scene3_point"):
                    out.append({"status":"HASH_RESOLVED","groupId":0,"blockId":24230448,
                                "exportedName":"bc3ae3e1","pathHash":m.SCENE_POINT3_HASH})
                else:
                    out.append({"status":"HASH_ABSENT","pathHash":"0x0000000000"})
            return out
        def sha(data):
            if data==b"index-source":return m.INDEX_SHA
            if data==b"original-area-control":return m.WORLD_AREA3_RAW_SHA
            return sha256(data).hexdigest()
        with TemporaryDirectory() as d:
            folder=Path(d)/"MiHoYoBinData"
            folder.mkdir()
            (folder/"0c934d1c.dat").write_bytes(b"original-area-control")
            payload=b"\xCB\x03\x01\x02\xFF"  # Synthetic bytes, no schema assignment
            (folder/"bc3ae3e1.dat").write_bytes(struct.pack("<I",len(payload))+payload)
            with patch.object(m,"parse_asset_index",return_value=index),\
                 patch.object(m,"query_asset_paths",side_effect=query),\
                 patch.object(m,"sha256",side_effect=sha):
                report=m.analyze(b"index-source",Path(d))
            self.assertEqual(report["scenesChecked"],13)
            self.assertEqual(report["statusCounts"],
                             {"HASH_ABSENT":12,"SOURCE_RAW_AND_FRAMING_VERIFIED":1})
            obj=report["assetRows"][0]
            self.assertEqual(obj["payloadBytes"],5)
            self.assertEqual(obj["firstLittleEndianU32"],"0x020103CB")
            self.assertFalse(obj["nativeScenePointRowSchemaDecoded"])
            self.assertFalse(obj["chestGadgetInstanceProven"])
            self.assertFalse(report["originalChestInstancePlacementProven"])

    def test_original_index_hash_cannot_be_omitted(self):
        with self.assertRaisesRegex(ValueError,"source-authenticated"):
            m.analyze(b"random untrusted bytes",Path("."))

if __name__=="__main__":
    unittest.main()
