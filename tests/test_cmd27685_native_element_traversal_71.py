"""Source-pinned actual native element traversal evidence regression."""
from importlib import util
from pathlib import Path
import json
import unittest
ROOT = Path(__file__).resolve().parents[1]
spec = util.spec_from_file_location("native_27685_element", ROOT / "scripts/audit-7.1-cmd27685-native-element-traversal.py")
m = util.module_from_spec(spec)
spec.loader.exec_module(m)
EVIDENCE = ROOT / "versions/7.1.0-global/analyses/progression/economy/7.1-cmd27685-native-element-traversal.json"


class NativeCollectionElement(unittest.TestCase):
    def test_verified_instructions_and_negative_semantic_boundary(self):
        report=json.loads(EVIDENCE.read_text(encoding="utf-8"))
        self.assertEqual(report["originalExeSha256"],m.PROFILE_71.exe_sha256)
        self.assertEqual(report["originalDerivedEvidence"]["ownerNativeMethodArtifactSha256"],m.OWNER_REPORT_SHA256)
        self.assertEqual(report["originalDerivedEvidence"]["consumerNativeMethodArtifactSha256"],m.CONSUMER_REPORT_SHA256)
        self.assertEqual(report["originalInstructionWitness"]["checkedInstructionCount"],
                         sum(len(x) for x in m.NATIVE_INSTRUCTIONS.values()))
        original=report["originalInstructionWitness"]
        self.assertEqual(original["onAcceptReadsMessageCollectionOffset"],"0x18")
        self.assertEqual(original["onAcceptReads32bitScalarFromElementOffset"],"0x98")
        self.assertFalse(original["element32bitScalarIsFieldOfRootPacket"])
        self.assertFalse(original["concreteElementClassProven"])
        self.assertFalse(original["scalarSemanticLevelProven"])
        self.assertFalse(original["scalarSemanticEntityIdProven"])
        self.assertFalse(original["staticInitializerLiteralInterpretedAsProtobufTag"])

    def test_fail_closed_native_opcode_anchor(self):
        good={"0xFCDF6B2": ["mov","edx, dword ptr [rax + 0x98]","8b9098000000"]}
        row=[{"rva":"0xFCDF6B2","mnemonic":"mov","operands":"edx, dword ptr [rax + 0x98]","bytes":"8b9098000000"}]
        m.verify_opcode_rows(row,good,instruction_address_field="rva",instruction_operand_field="operands")
        row[0]["bytes"]="8b9094000000"
        with self.assertRaisesRegex(ValueError,"native instruction changed"):
            m.verify_opcode_rows(row,good,instruction_address_field="rva",instruction_operand_field="operands")

    def test_falsified_derived_report_sha(self):
        with self.assertRaisesRegex(ValueError,"SHA-256 mismatch"):
            m.build(b"junk",b"junk")

if __name__=="__main__":
    unittest.main()
