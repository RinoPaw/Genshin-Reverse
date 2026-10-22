"""Original 7.1 numeric registry and protocol-owner data gates."""
from __future__ import annotations
from importlib import util
from pathlib import Path
import csv
import hashlib
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
s=util.spec_from_file_location("scene_entity_original",ROOT/"scripts/probe-7.1-scene-entity-protocol-owner.py")
m=util.module_from_spec(s)
s.loader.exec_module(m)


class NativeSceneEntityProbe(unittest.TestCase):
    def test_native_owner_anchor(self):
        self.assertEqual((m.CMD,m.OWNER,m.OWNER_INDEX,m.CMD_GETTER_RVA),
                         (27685,"KIIKIELOHOG",65670,0xC16BDD0))

    def test_source_blob_hash(self):
        raw=b"test"
        with tempfile.TemporaryDirectory() as td:
            f=Path(td)/"x"
            f.write_bytes(raw)
            self.assertEqual(m.git_blob(f),
                hashlib.sha1(b"blob 4"+bytes([0])+raw).hexdigest())

    def test_registry_positive_controls(self):
        with tempfile.TemporaryDirectory() as td:
            f=Path(td)/"registry.csv"
            with f.open("w",encoding="utf-8",newline="") as stream:
                w=csv.DictWriter(stream,fieldnames=[
                    "cmd_id","type_name","type_definition_index","get_cmd_id_rva"])
                w.writeheader()
                w.writerow(dict(cmd_id=27685,type_name=m.OWNER,
                                type_definition_index=m.OWNER_INDEX,get_cmd_id_rva="0xC16BDD0"))
                w.writerow(dict(cmd_id=9369,type_name="DMMJNICDOHM",
                                type_definition_index=84249,get_cmd_id_rva="0xC87EA60"))
                w.writerow(dict(cmd_id=22899,type_name="ONKOPMILDMF",
                                type_definition_index=87483,get_cmd_id_rva="0x9FDADC0"))
            self.assertEqual(len(m.require_registry(f)),3)
            f.write_text(f.read_text().replace("KIIKIELOHOG","BADIDENTITY"))
            with self.assertRaisesRegex(ValueError,"owner identity changed"):
                m.require_registry(f)


if __name__=="__main__":
    unittest.main()
