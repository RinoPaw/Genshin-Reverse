"""Source-control gate for Global 7.1 native CmdId27685 consumers."""
from importlib import util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=util.spec_from_file_location("source_27685",ROOT/"scripts/probe-7.1-cmd27685-native-consumers.py")
m=util.module_from_spec(spec)
spec.loader.exec_module(m)

class PacketNativeOwner(unittest.TestCase):
    def test_fixed_original_native_consumers(self):
        self.assertEqual(set(m.EXPECTED),{190070,190137,190172,190174})
        self.assertEqual(m.EXPECTED[190174],("JLDCJCKHJEM","OnAccept",0xFCDF5D0))

    def test_positive_source_identity_gate(self):
        source={"sample":m.PROFILE_71.identity,
                "exe_sha256":m.PROFILE_71.exe_sha256,
                "metadata_sha256":m.PROFILE_71.metadata_sha256,
                "control_validation_passed":True,
                "rows":[{"cmd_id":27685,"type_name":"KIIKIELOHOG",
                         "known_handler_owner_hit_count":0,
                         "all_hits":[{"method_index":str(k),"owner_type":x[0],
                            "method_name":x[1],"method_rva":f"0x{x[2]:X}",
                            "parameter_ordinal":0} for k,x in m.EXPECTED.items()]}]}
        self.assertEqual(len(m.verify_hits(source)),4)
        source["control_validation_passed"]=False
        with self.assertRaisesRegex(ValueError,"controls failed"):
            m.verify_hits(source)

if __name__=="__main__":
    unittest.main()
