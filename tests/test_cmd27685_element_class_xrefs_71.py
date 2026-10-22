"""Exact Global 7.1 CmdId27685 TypeInfo source reference gates."""
from importlib import util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=util.spec_from_file_location("xrefs27685",ROOT/"scripts/probe-7.1-cmd27685-element-class-xrefs.py")
m=util.module_from_spec(spec)
spec.loader.exec_module(m)

class OriginalXrefs(unittest.TestCase):
    def test_original_class_slot_addresses(self):
        self.assertEqual(m.target_rva(m.ANCHORS["collectionAllocationTypeInfo"]),0x5804798)
        self.assertEqual(m.target_rva(m.ANCHORS["collectionConstructorAuxiliaryTypeInfo"]),0x590CE30)
        self.assertEqual(m.target_rva(m.ANCHORS["repeatedElementStaticTypeInfo"]),0x57D1928)
        self.assertEqual(m.target_rva(m.ANCHORS["staticCodecAllocationTypeInfo"]),0x582D490)
        self.assertEqual(len(m.ANCHORS),4)

    def test_exact_original_positive_controls_and_unknown_identity(self):
        report={"matches":{}}
        for name,row in m.ANCHORS.items():
            addr=m.target_rva(row)
            report["matches"][f"0x{addr:X}"]=[{
                "instruction_rva":f"0x{row['instructionRva']:X}",
                "access":"read","mnemonic":"mov",
                "instruction_hex":"488b0500000000","caller_methods":[]}]
        result=m.check_xrefs(report)
        self.assertEqual(len(result),4)
        self.assertTrue(all(not x["actualRuntimeIl2CppClassIdentityVerified"]
                            for x in result.values()))
        report["matches"]["0x57D1928"]=[]
        with self.assertRaisesRegex(ValueError,"positive control missing"):
            m.check_xrefs(report)

if __name__=="__main__":
    unittest.main()
