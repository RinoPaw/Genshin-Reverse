"""Source-control gate for Global 7.1 native CmdId27685 consumers."""
from importlib import util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=util.spec_from_file_location("source_27685",ROOT/"scripts/probe-7.1-cmd27685-native-consumers.py")
m=util.module_from_spec(spec)
spec.loader.exec_module(m)

class PacketNativeOwner(unittest.TestCase):
    def test_source_pinned_published_original_protocol_boundary(self):
        import json
        f=ROOT/"versions/7.1.0-global/analyses/progression/economy/7.1-cmd27685-original-native-consumers.json"
        obj=json.loads(f.read_text(encoding="utf-8"))
        self.assertEqual(obj["source"]["originalExeSha256"],m.PROFILE_71.exe_sha256)
        self.assertEqual(obj["source"]["originalMetadataSha256"],m.PROFILE_71.metadata_sha256)
        self.assertEqual(obj["originalMessageIdentity"]["cmdId"],27685)
        self.assertEqual(obj["originalMessageIdentity"]["originalFieldCount"],4)
        self.assertEqual(obj["originalMessageIdentity"]["originalMethodCount"],14)
        self.assertEqual(obj["originalWholeMethodParameterScan"]["exactMessageTypeMethodParameterReferences"],5)
        self.assertTrue(obj["originalWholeMethodParameterScan"]["knownOriginalHandlerControlsPassed"])
        self.assertEqual({x["methodIndex"] for x in obj["originalExternalNativeMethods"]},set(m.EXPECTED))
        self.assertFalse(obj["originalNativeSceneInstanceLevelFieldProven"])
        self.assertFalse(obj["originalNativePropLevel4001ConsumerProven"])
        self.assertFalse(obj["externalForkHypothesis"]["provenNativeSemanticMapping"])

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
