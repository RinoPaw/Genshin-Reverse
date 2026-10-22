"""Original 7.1 Cmd27685 varint field2 keyed hash-container evidence gates."""
from importlib import util
from pathlib import Path
import json
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=util.spec_from_file_location("native_field2_keyed",ROOT/"scripts/audit-7.1-cmd27685-field2-keyed-container.py")
m=util.module_from_spec(spec)
spec.loader.exec_module(m)

class Field2Keyed(unittest.TestCase):
    def test_published_source_identities_and_scope(self):
        obj=json.loads((ROOT/"versions/7.1.0-global/analyses/progression/economy/7.1-cmd27685-field2-keyed-container-native-flow.json").read_text(encoding="utf-8"))
        self.assertEqual(obj["originalExeSha256"],m.PROFILE_71.exe_sha256)
        self.assertEqual(obj["evidence"]["originalNativeCalleeJsonSha256"],m.CALLEE_SHA)
        self.assertEqual(obj["evidence"]["originalCollectorOwnerJsonSha256"],m.OWNER_SHA)
        self.assertEqual(obj["originalInstructionWitness"],m.ANCHORS)
        self.assertEqual(obj["collector"]["originalNativeLookupCall"]["to"],"0x184EE680")
        self.assertEqual(obj["collector"]["originalNativeInsertionCall"]["to"],"0x184EE960")
        self.assertTrue(obj["nativeHelperProof"]["lookupTraversesBucketChain"])
        self.assertTrue(obj["nativeHelperProof"]["lookupUsesNegativeOneIndexSentinel"])
        self.assertFalse(obj["collector"]["fieldAtCollectorPlus0x28ConcreteGenericTypeProven"])
        self.assertFalse(obj["nativeHelperProof"]["exactConcreteGenericMethodMetadataPresent"])

    def test_strict_native_opcode_check(self):
        sample=[{"rva":"0x184EE70A","mnemonic":"mov","operands":"ebx, 0xffffffff","hex":"bbffffffff"}]
        self.assertEqual(m.check_insns(sample,{"0x184EE70A":["mov","ebx, 0xffffffff","bbffffffff"]},op_key="hex"),1)
        sample[0]["hex"]="90"
        with self.assertRaisesRegex(ValueError,"native instruction mismatch"):
            m.check_insns(sample,{"0x184EE70A":["mov","ebx, 0xffffffff","bbffffffff"]},op_key="hex")

    def test_unknown_original_artifacts_rejected(self):
        with self.assertRaisesRegex(ValueError,"artifact hash mismatch"):
            m.audit(b"missing",b"missing")

if __name__=="__main__":
    unittest.main()
