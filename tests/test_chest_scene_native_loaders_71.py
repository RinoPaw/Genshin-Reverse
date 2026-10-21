"""Synthetic source and native disassembly gates for SceneTag/SceneExcel loaders."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

from genshinre import scenebin71
from genshinre.nativeprofile import PROFILE_71

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/audit-7.1-scene-native-loaders.py"
REPORT = (ROOT / "versions/7.1.0-global/analyses/progression/economy"
          / "7.1-chest-native-scene-table-loader-evidence.json")
spec = importlib.util.spec_from_file_location("native_scene_loader_71", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class TestOriginalSceneNativeLoaders71(unittest.TestCase):
    def test_committed_evidence_preserves_native_headers_and_dispatch_boundary(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertEqual(report["exeSha256"], PROFILE_71.exe_sha256)
        self.assertEqual(report["status"],
                         "EXACT_7_1_SCENE_EXCEL_AND_TAG_NATIVE_HEADER_LOOP_CONFIRMED__ROW_FIELDS_UNKNOWN")
        self.assertEqual(set(report["nativeTables"]), set(probe.NATIVE))
        for name, native in probe.NATIVE.items():
            entry = report["nativeTables"][name]
            source = scenebin71.SOURCES[name]
            self.assertEqual(entry["nativeRowCount"], source["count"])
            self.assertEqual(entry["nativeMethodIndex"], source["method_index"])
            self.assertEqual(int(entry["nativeLoaderRva"], 16), source["loader_rva"])
            self.assertEqual(entry["matchedInstructionAnchors"], len(native["anchors"]))
            self.assertEqual(entry["nativeDisassemblySha256"], native["disassemblySha256"])
            self.assertTrue(entry["headerAndLoopVerifiedFromOriginalClient"])
            self.assertFalse(entry["rowSchemaDecoded"])
            self.assertFalse(entry["sceneGadgetOwnershipProven"])
            self.assertFalse(entry["serverDropTagProven"])
            self.assertEqual(entry["rowReaderDispatch"], "virtual CALL [row.vtable + 0xF0]")
            self.assertEqual(entry["rowKeyMemoryOffset"], f"0x{source['key_offset']:X}")

    @staticmethod
    def fake_materials():
        fake_disassembly = {}
        fake_raw = {}
        sources = {}
        native = {}
        for name, origin in scenebin71.SOURCES.items():
            source = dict(origin)
            native_entry = copy.deepcopy(probe.NATIVE[name])
            body = struct.pack("<I", (
                (source["count"] ^ source["immediate"]) if source["op"] == "xor"
                else (source["count"] - source["immediate"]) & 0xFFFFFFFF
            )) + b"fictional-rows-unparsed"
            raw = struct.pack("<I", len(body)) + body
            source["raw_sha"] = hashlib.sha256(raw).hexdigest()
            source["payload_sha"] = hashlib.sha256(body).hexdigest()
            file = json.dumps({
                "exe_sha256": PROFILE_71.exe_sha256,
                "start_rva": f"0x{source['loader_rva']:X}",
                "instructions": [
                    {"rva": at, "mnemonic": mnemonic, "op_str": operands}
                    for at, mnemonic, operands in native_entry["anchors"]
                ],
            }).encode("utf-8")
            native_entry["disassemblySha256"] = hashlib.sha256(file).hexdigest()
            fake_disassembly[name] = file
            fake_raw[name] = raw
            sources[name] = source
            native[name] = native_entry
        return sources, native, fake_disassembly, fake_raw

    def test_native_instruction_and_raw_source_witnesses_are_both_mandatory(self):
        sources, native, disassembly, raw = self.fake_materials()
        with (patch.dict(scenebin71.SOURCES, sources),
              patch.dict(probe.NATIVE, native)):
            report = probe.verify_native(disassembly, raw)
            self.assertEqual(report["nativeTables"]["SceneTagConfigData"]
                             ["nativeRowCount"], 1147)
            self.assertEqual(report["nativeTables"]["SceneExcelConfigData"]
                             ["nativeRowCount"], 2377)
            bad = dict(disassembly)
            bad["SceneTagConfigData"] += b"x"
            with self.assertRaisesRegex(ValueError, "disassembly SHA-256 mismatch"):
                probe.verify_native(bad, raw)
            wrong = dict(raw)
            wrong["SceneExcelConfigData"] += b"x"
            with self.assertRaisesRegex(scenebin71.SceneBin71Error, "raw export SHA-256"):
                probe.verify_native(disassembly, wrong)

    def test_original_client_scene_tag_does_not_authorize_server_loot(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertTrue(any("no authenticated relationship" in note
                            for note in report["limitations"]))
        tag = report["nativeTables"]["SceneTagConfigData"]
        self.assertFalse(tag["rowSchemaDecoded"])
        self.assertFalse(tag["serverDropTagProven"])
        self.assertFalse(tag["sceneGadgetOwnershipProven"])
        self.assertEqual(tag["rowReaderDispatch"],
                         "virtual CALL [row.vtable + 0xF0]")

    def test_unrecognized_loader_anchor_rejected(self):
        sources, native, disassembly, raw = self.fake_materials()
        item = copy.deepcopy(native["SceneTagConfigData"])
        anchors = list(item["anchors"])
        at, ins, _ = anchors[0]
        anchors[0] = (at, ins, "edi, 0xf16a9d34")
        item["anchors"] = tuple(anchors)
        native["SceneTagConfigData"] = item
        with (patch.dict(scenebin71.SOURCES, sources),
              patch.dict(probe.NATIVE, native)):
            with self.assertRaisesRegex(ValueError, "native instruction mismatch"):
                probe.verify_native(disassembly, raw)


if __name__ == "__main__":
    unittest.main()
