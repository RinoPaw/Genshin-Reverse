"""Original GadgetExcel ID bytes are bounded heuristic controls in one Unity block."""
from importlib import util
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
s=util.spec_from_file_location("native_gadget_contact",ROOT/"scripts/probe-7.1-worldarea-native-gadget-id-contacts.py")
m=util.module_from_spec(s);s.loader.exec_module(m)

class NativeGadgetByteContacts(unittest.TestCase):
    def test_native_gadget_source_ids_and_literal_names(self):
        rows=m.native_gadget_ids()
        self.assertEqual(len(rows),20)
        self.assertEqual(rows[70210011],"SceneObj_Chest_Default_Lv1")
        self.assertEqual(rows[70210054],"SceneObj_Chest_Frozen_Lv5")

    def test_native_matches_and_synthetic_diagnostics_not_semantics(self):
        ids={70210011:"SceneObj_Chest_Default_Lv1",70210012:"SceneObj_Chest_Locked_Lv1"}
        original=70210011
        control=m.CONTROL_MAGIC[0]
        raw=(b"\x00"*4+original.to_bytes(4,"little")+b"\x01"+
             original.to_bytes(4,"little")+control.to_bytes(4,"little"))
        result=m.scan_bytes(raw,ids)
        self.assertEqual(result["counts"]["native"][original],2)
        self.assertEqual(result["counts"]["diagnostic"][control],1)
        self.assertEqual(result["aligned"]["native"],1)

    def test_no_empty_schema_promotion(self):
        result=m.scan_bytes(b"no matching bytes", {70210011:"SceneObj_Chest_Default_Lv1"})
        self.assertFalse(result["counts"]["native"])

if __name__=="__main__":unittest.main()
