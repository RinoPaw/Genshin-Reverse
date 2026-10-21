"""Regression for bounded 7.1 Scene manager generic field/native pointer probes."""
from __future__ import annotations

import csv
import importlib.util
import struct
import tempfile
from pathlib import Path
import unittest

from genshinre.nativeprofile import PROFILE_71

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "original_scene_generic_71", ROOT / "scripts/probe-7.1-scene-manager-genericinst.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class FakePE:
    image_base = 0x140000000
    def __init__(self, addresses):
        self.addresses = addresses
    def read_rva(self, rva, n):
        return self.addresses.get((self.image_base+rva, n), b"")


class TestSceneManagerGeneric71(unittest.TestCase):
    def test_original_field_owners_with_two_fixed_metadata_fields(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "fields.csv"
            with path.open("w", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=[
                    "type_definition_index","type_name","field_name",
                    "field_type", "field_type_index"])
                writer.writeheader()
                for owner, (index, type_name) in probe.OWNERS.items():
                    writer.writerow({"type_definition_index":index,
                        "type_name": type_name, "field_name":"PAAGPEHCJFI",
                        "field_type":"kind_0x15", "field_type_index":"123"})
                    writer.writerow({"type_definition_index":index,
                        "type_name": type_name, "field_name":"PBLMHNBIAJL",
                        "field_type":"bool", "field_type_index":"124"})
            rows = probe.owner_fields(path)
            self.assertEqual(len(rows["SceneTagConfigData"]), 2)
            self.assertEqual(len(rows["SceneExcelConfigData"]), 2)
            content = path.read_text()
            path.write_text(content.replace("kind_0x15","kind_0x12"))
            with self.assertRaisesRegex(ValueError, "generic manager field"):
                probe.owner_fields(path)

    def test_unmapped_type_data_stays_unverified(self):
        generic_type = bytearray(16)
        struct.pack_into("<Q", generic_type, 0, 0x150001000)
        generic_type[10] = 0x15
        result = probe.trace_pointer_chain(FakePE({}), bytes(generic_type))
        self.assertFalse(result["genericClassDataFileBacked"])
        self.assertEqual(result["genericArgumentTypeIndexMapping"], "UNVERIFIED")
        self.assertEqual(result["genericArgumentTypes"], [])

    def test_candidate_generic_class_chain_is_explicitly_hypothetical(self):
        base = 0x140000000
        class_va, inst_va, array_va = [base+x for x in (0x1000,0x2000,0x3000)]
        uint_va, row_va = [base+x for x in (0x4000,0x5000)]
        entry = bytearray(16)
        struct.pack_into("<Q", entry, 0, class_va)
        entry[10] = 0x15
        generic_class = struct.pack("<QQQQ", base+0x1111, inst_va, 0, 0)
        generic_inst = struct.pack("<I4xQ", 2, array_va)
        pointers = struct.pack("<QQ", uint_va,row_va)
        uint_type = bytearray(16); uint_type[10]=0x09
        row_type = bytearray(16); row_type[10]=0x12
        struct.pack_into("<I", row_type, 0, 84296)
        pe=FakePE({(class_va, 32):generic_class,
            (inst_va,16):generic_inst,
            (array_va,16):pointers,
            (uint_va,16):bytes(uint_type),
            (row_va,16):bytes(row_type)})
        result=probe.trace_pointer_chain(pe,bytes(entry))
        self.assertTrue(result["genericClassDataFileBacked"])
        self.assertTrue(result["classContextFileBacked"])
        self.assertTrue(result["classGenericArgsFileBacked"])
        self.assertEqual(result["classGenericArgCountCandidate"],2)
        self.assertEqual([r["kindName"] for r in result["genericArgumentTypes"]],
                         ["u4","class"])
        self.assertEqual(result["genericArgumentTypes"][1]["typeDefinitionIndexCandidate"],84296)
        self.assertEqual(result["genericArgumentTypeIndexMapping"], "UNVERIFIED")

    def test_bounded_generic_argument_count(self):
        self.assertEqual(probe.MAX_ARGS, 4)
        self.assertEqual(probe.OWNERS["SceneTagConfigData"][0],84296)
        self.assertEqual(probe.OWNERS["SceneExcelConfigData"][0],35441)


if __name__ == "__main__":
    unittest.main()
