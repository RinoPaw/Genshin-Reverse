"""Exact sample Gadget auxiliary manager native type probe gates."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("gadget_aux_manager_native",ROOT/"scripts/probe-7.1-gadget-aux-manager-native-types.py")
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class GadgetAuxManagerNative(unittest.TestCase):
    def test_original_owner_type_indices_are_pinned(self):
        self.assertEqual(module.MANAGER_TYPES["GadgetPropExcelConfigData"],(28984,"CLOHJDMMODM"))
        self.assertEqual(module.MANAGER_TYPES["GadgetInteractExcelConfigData"],(28382,"GAMAJLKMDJO"))
        self.assertEqual(module.STATIC_SLOTS["GadgetPropExcelConfigData"],0x57DAF50)
        self.assertEqual(module.STATIC_SLOTS["GadgetInteractExcelConfigData"],0x57FA548)

    def test_manager_field_membership_and_type_indexes(self):
        import csv
        with tempfile.TemporaryDirectory() as dir:
            file=Path(dir)/"fields.csv"
            with file.open("w",encoding="utf-8",newline="") as stream:
                writer=csv.DictWriter(stream,fieldnames=[
                    "field_index","field_name","type_definition_index",
                    "type_name","field_type_index","field_type"])
                writer.writeheader()
                writer.writerow({"field_index":100,"field_name":"A",
                    "type_definition_index":28984,"type_name":"CLOHJDMMODM",
                    "field_type_index":20,"field_type":"kind_0x15"})
                writer.writerow({"field_index":200,"field_name":"B",
                    "type_definition_index":28382,"type_name":"GAMAJLKMDJO",
                    "field_type_index":30,"field_type":"kind_0x02"})
            result=module.get_manager_fields(file)
            self.assertEqual(result["GadgetPropExcelConfigData"][0]["fieldTypeIndex"],20)
            self.assertEqual(result["GadgetInteractExcelConfigData"][0]["fieldName"],"B")
            text=file.read_text(encoding="utf-8").replace("CLOHJDMMODM","WRONGTYPE")
            file.write_text(text,encoding="utf-8")
            with self.assertRaisesRegex(ValueError,"owner type label changed"):
                module.get_manager_fields(file)


if __name__=="__main__":
    unittest.main()
