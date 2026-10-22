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


    def test_source_authenticated_parent_and_child_native_chain_report(self):
        path=EVIDENCE/"7.1-original-scene-entity-float-parent-native-chain.json"
        report=json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(report["originalExeSha256"],m.PROFILE_71.exe_sha256)
        self.assertEqual(report["originalMetadataSha256"],m.PROFILE_71.metadata_sha256)
        self.assertEqual(report["artifactId"],12404195207)
        self.assertEqual(report["typedOriginalChildField"],m.verify_priors(self.el,self.nested))
        parent=report["parentReader"]
        self.assertEqual(parent["methodRva"],f"0x{m.PARENT_RVA:X}")
        self.assertEqual(parent["sourceSha256"],m.PARENT_SHA256)
        self.assertEqual(parent["decodedInstructionCount"],708)
        self.assertEqual(parent["directCallCount"],88)
        self.assertEqual(parent["rawParentFieldAccessCount"],54)
        self.assertFalse(parent["directCallToChildReaderFound"])
        self.assertFalse(parent["directCallToChildCtorFound"])
        self.assertEqual(parent["witness"]["field2Store"]["rva"],
                         f"0x{m.KNOWN_WIRE2_STORE:X}")
        self.assertEqual(report["additionalNativeMethods"]["elementCopyFrom"]["methodRva"],
                         "0xB43D570")
        self.assertEqual(report["additionalNativeMethods"]["elementCopyFrom"]["decodedInstructions"],505)
        self.assertEqual(report["additionalNativeMethods"]["elementCopyFrom"]["directCallCount"],61)
        self.assertEqual(report["additionalNativeMethods"]["elementCopyFrom"]["directChildCopyFromCallCount"],0)
        child=report["verifiedOriginalChildReader"]
        self.assertEqual(child["sourceSha256"],m.CHILD_SHA256)
        self.assertEqual([x["originalRva"] for x in child["verifiedFloatStoreInstructions"]],
                         [f"0x{v:X}" for v in m.FLOAT_STORES])
        self.assertTrue(report["claims"]["childTypeFromOriginalMetadata"])
        self.assertFalse(report["claims"]["nativeParentObjectOffsetForNamedChildKnown"])
        self.assertFalse(report["claims"]["originalFloatMeaningPositionProven"])
        self.assertFalse(report["claims"]["packetDirectionProven"])
        self.assertFalse(report["claims"]["originalServerPlacementOwnershipProven"])

if __name__=="__main__":
    unittest.main()
