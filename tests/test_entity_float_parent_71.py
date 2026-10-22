"""Exact Global 7.1 entity float nested-reader source boundary tests."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("floatparent71",ROOT/"scripts/probe-7.1-entity-float-parent.py")
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
EVIDENCE=ROOT/"versions/7.1.0-global/analyses/progression/economy/"

class FloatParentNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.el=json.loads((EVIDENCE/"7.1-original-cmd27685-element-metadata-reader-census.json").read_text(encoding="utf-8"))
        cls.nested=json.loads((EVIDENCE/"7.1-original-scene-entity-nested-native-type-evidence.json").read_text(encoding="utf-8"))

    def test_source_pinned_typed_child_relation(self):
        f=m.verify_priors(self.el,self.nested)
        self.assertEqual(f["originalFieldIndex"],423371)
        self.assertEqual(f["originalObfuscatedToken"],"DLOEKFLGJCG")
        self.assertEqual(f["originalType"],"ABOOLMJBDKE")

    def test_wrong_semantic_owner_rejected(self):
        bad=json.loads(json.dumps(self.el))
        field=next(x for x in bad["metadata"]["elementFields"] if x["originalFieldIndex"]==m.ELEMENT_FIELD_INDEX)
        field["originalType"]="Vector3"
        with self.assertRaisesRegex(ValueError,"typed child-field"):
            m.verify_priors(bad,self.nested)

    def test_native_coordinates_and_original_writer_anchors(self):
        self.assertEqual(m.PARENT_RVA,0xB43A2A0)
        self.assertEqual(m.CHILD_RVA,0x11B25D70)
        self.assertEqual(m.CHILD_SHA256,self.nested["floatNestedTypeReaders"]["ABOOLMJBDKE"]["readWindowSha256"])
        self.assertEqual(set(m.FLOAT_STORES),{0x11B25DD4,0x11B25E26,0x11B25EA8})
        self.assertFalse(self.nested["conclusions"]["coordinateSemanticProven"])

    def test_disassembly_uses_executable_rva(self):
        class Ins:
            address=0x140000000+0xB43A328
            mnemonic="cmp"
            op_str="eax, 0x10"
            bytes=b"\x83\xf8\x10"
        class Decoder:
            def disasm(self,raw,address):
                assert address==0x140000000+0xB43A2A0
                yield Ins()
        out=m.decode(Decoder(),b"\x83\xf8\x10",0x140000000,0xB43A2A0)
        self.assertEqual(out[0]["rva"],"0xB43A328")
        self.assertEqual(out[0]["opcode"],"83f810")

if __name__=="__main__":
    unittest.main()
