"""Synthetic invariants for original 7.1 nested native field owner census."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts/probe-7.1-cmd27685-nested-native-types.py"
spec=importlib.util.spec_from_file_location("nested71",SCRIPT)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
PRIOR=ROOT/"versions/7.1.0-global/analyses/progression/economy/7.1-original-cmd27685-element-metadata-reader-census.json"


class NestedOriginalTypes(unittest.TestCase):
    def test_exact_original_element_source(self):
        report=json.loads(PRIOR.read_text(encoding="utf-8"))
        self.assertEqual(report["elementTypeDefinitionIndex"],m.ELEMENT_INDEX)
        self.assertEqual(report["metadata"]["elementFields"][0]["originalType"],m.REPEATED_TYPE)
        names=m.nested_type_names(report["metadata"]["elementFields"])
        self.assertEqual(sum(x["originalType"]==m.REPEATED_TYPE
                            for x in report["metadata"]["elementFields"]),m.REPEATED_COUNT)
        self.assertIn(m.REPEATED_TYPE,names)

    def test_reject_repeated_type_drift(self):
        report=json.loads(PRIOR.read_text(encoding="utf-8"))
        changed=[dict(x) for x in report["metadata"]["elementFields"]]
        changed[0]["originalType"]="not-the-original-type"
        with self.assertRaisesRegex(ValueError,"multiplicity drift"):
            m.nested_type_names(changed)

    def test_native_membership_uses_source_pinned_fields(self):
        src=json.loads(PRIOR.read_text(encoding="utf-8"))
        original=src["metadata"]["elementFields"]
        names=m.nested_type_names(original)
        owners={m.ELEMENT:85506}
        owners.update({name:2000+i for i,name in enumerate(names)})
        with TemporaryDirectory() as tmp:
            root=Path(tmp)
            typ=root/"types.csv"
            fields=root/"fields.csv"
            methods=root/"methods.csv"
            typ.write_text("type_definition_index,type_name,parent_type\n"+
                "".join(f"{idx},{name},\n" for name,idx in owners.items()),encoding="utf-8")
            rows=[f'{85506},{m.ELEMENT},{f["originalFieldIndex"]},{f["originalObfuscatedToken"]},{f["originalType"]},{f["originalRuntimeTypeIndex"]},\n'
                  for f in original]
            hcd=owners[m.REPEATED_TYPE]
            rows.extend(f"{hcd},{m.REPEATED_TYPE},{100+i},N{i},float32,{100+i},\n"
                        for i in range(3))
            fields.write_text("type_definition_index,type_name,field_index,field_name,field_type,field_type_index,offset\n"+
                              "".join(rows),encoding="utf-8")
            methods.write_text("type_definition_index,type_name,method_index,method_name,rva,parameter_types\n"
                +f"{hcd},{m.REPEATED_TYPE},705939,{m.READER_TOKEN},0x1000,[]\n",encoding="utf-8")
            with patch.object(m,"git_blob",return_value=m.FIELDS_BLOB),patch.object(m,"METHODS_BLOB",m.FIELDS_BLOB):
                result=m.member_census(typ,fields,methods,src)
            self.assertEqual(result["sourceNativeTypes"][m.REPEATED_TYPE]["declaredFloat32FieldCount"],3)
            self.assertTrue(result["sourceNativeTypes"][m.REPEATED_TYPE]["allDeclaredFieldsAreFloat32"])
            self.assertEqual(len(result["repeatedNestedFieldTokens"]),5)
            self.assertEqual(len(result["sourceNativeTypes"][m.ELEMENT]["fields"]),27)


    def test_published_original_source_evidence(self):
        report_path=(ROOT/"versions/7.1.0-global/analyses/progression/economy/"
                     "7.1-original-scene-entity-nested-native-type-evidence.json")
        report=json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["originalExeSha256"],m.PROFILE_71.exe_sha256)
        self.assertEqual(report["metadataFieldGitBlob"],m.FIELDS_BLOB)
        self.assertEqual(report["metadataMethodGitBlob"],m.METHODS_BLOB)
        self.assertEqual(report["source"]["artifactId"],12402624359)
        self.assertEqual(report["typeCensus"]["repeatedNestedType"],m.REPEATED_TYPE)
        self.assertEqual(len(report["typeCensus"]["repeatedNestedFieldTokens"]),5)
        self.assertEqual(len(report["typeCensus"]["distinctDirectNestedTypes"]),9)
        hcd=report["typeCensus"]["sourceNativeTypes"][m.REPEATED_TYPE]
        self.assertEqual(hcd["fieldTypeHistogram"],
            {"Il2CppRuntimeClassHandle":1,"int32":1,"uint32":1})
        self.assertEqual(hcd["declaredFloat32FieldCount"],0)
        self.assertFalse(report["repeatedNestedTypeReader"]
                         ["originalReaderMethodUniquelyIdentified"])
        ab=report["typeCensus"]["sourceNativeTypes"]["ABOOLMJBDKE"]
        self.assertEqual(ab["declaredFloat32FieldCount"],3)
        native=report["floatNestedTypeReaders"]["ABOOLMJBDKE"]
        self.assertEqual(native["readerMethodRva"],"0x11B25D70")
        self.assertEqual(native["readWindowSha256"],
            "f9b555f094537c2660d50eddb71cf38629df5ba47fbd310071a0d0da941ddb32")
        self.assertEqual([x["operands"] for x in report["nativeScalarFloatStores"]],
            ["dword ptr [rdi + 0x20], xmm0",
             "dword ptr [rdi + 0x1c], xmm0",
             "dword ptr [rdi + 0x18], xmm0"])
        self.assertFalse(report["conclusions"]["coordinateSemanticProven"])
        self.assertFalse(report["conclusions"]["clientStaticChestPlacementProven"])
        self.assertFalse(report["conclusions"]["originalServerPacketDirectionProven"])


if __name__=="__main__":
    unittest.main()
