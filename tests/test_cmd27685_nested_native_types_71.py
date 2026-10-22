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


if __name__=="__main__":
    unittest.main()
