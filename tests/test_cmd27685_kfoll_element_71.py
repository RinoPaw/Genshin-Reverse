"""Strict source-scoped Global 7.1 CmdId27685 element field2 regressions."""
from importlib import util
from pathlib import Path
import json
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=util.spec_from_file_location("native_27685_kfoll",ROOT/"scripts/audit-7.1-cmd27685-kfoll-element.py")
module=util.module_from_spec(spec)
spec.loader.exec_module(module)


class KFOLLElementNative(unittest.TestCase):
    def test_published_verified_native_boundaries(self):
        report=json.loads((ROOT/"versions/7.1.0-global/analyses/progression/economy/7.1-cmd27685-kfoll-element-wire-field2.json").read_text(encoding="utf-8"))
        self.assertEqual(report["originalExeSha256"],module.PROFILE_71.exe_sha256)
        self.assertEqual(report["evidence"]["originalRvaXrefArtifactSha256"],module.XREF_SHA256)
        self.assertEqual(report["evidence"]["originalFieldOffsetArtifactSha256"],module.NATIVE_SHA256)
        self.assertEqual(report["elementType"]["obfuscatedClass"],"KFOLLNPEMHH")
        self.assertEqual(report["elementType"]["sourceClassStaticSlotRva"],"0x57D1928")
        self.assertEqual(report["elementType"]["crossTypeEdge"]["nativeCopyFromTargetRva"],"0xB43D570")
        self.assertEqual(report["field"]["objectMemoryOffset"],"0x98")
        self.assertEqual(report["field"]["nativeWireKeyBranchCompare"],"0x10")
        self.assertEqual(report["field"]["interpretedProtocolWireFieldNumber"],2)
        self.assertTrue(report["field"]["externalConsumerReadsIndexedElement"])
        self.assertFalse(report["elementType"]["runtimeGenericArgumentRegistrationIndependentlyResolved"])
        self.assertIsNone(report["field"]["confirmedNativeFieldSemanticName"])
        self.assertFalse(report["field"]["provenOriginalSceneLevel"])
        self.assertFalse(report["nativePacket"]["originalDirectionVerified"])

    def test_original_source_verifier_rejects_unknown_artifacts(self):
        with self.assertRaisesRegex(ValueError,"SHA-256 mismatch"):
            module.audit(b"edited xref",b"edited native")

    def test_native_instruction_semantics_gate(self):
        original={"rva":"0xB43A342","mnemonic":"mov","operand":"dword ptr [r12 + 0x98], eax"}
        ctx=[{"rva":"0xB43A328","mnemonic":"cmp","operand":"eax, 0x10"}]
        self.assertTrue(module.context_op({"context":ctx},"0xB43A328","cmp","eax, 0x10"))
        self.assertFalse(module.context_op({"context":ctx},"0xB43A328","cmp","eax, 0x18"))


if __name__=="__main__":
    unittest.main()
