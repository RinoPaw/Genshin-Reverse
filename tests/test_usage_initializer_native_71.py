"""Original Global 7.1 metadata usage initializer source boundary guards."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts/probe-7.1-usage-initializer-native.py"
spec=importlib.util.spec_from_file_location("init_native_71",SCRIPT)
s=importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)

class OriginalUsageInitializer(unittest.TestCase):
    def test_original_source_identity(self):
        p=json.loads((ROOT/s.PRIOR).read_text(encoding="utf-8"))
        self.assertEqual(p["originalExecutableSha256"],s.PROFILE_71.exe_sha256)
        self.assertEqual(p["originalMetadataSha256"],s.PROFILE_71.metadata_sha256)
        self.assertEqual(p["sourceOriginalUsageLayout"]["originalCandidateListCount"],311730)
        self.assertEqual(s.INITIALIZER_RVA,0x523400)
        self.assertEqual(s.ROOT_RVA,0x5AD52A8)

    def test_original_method_blob_hash_guard(self):
        with tempfile.TemporaryDirectory() as d:
            bogus=Path(d)/"methods.csv"
            bogus.write_text("not original",encoding="utf-8")
            with patch.object(s,"git_blob",return_value="bad"):
                with self.assertRaisesRegex(ValueError,"methods source drift"):
                    s.inspect(Path("missing"),bogus,ROOT/s.PRIOR)
    def test_native_source_kind1_writes_runtime_registration_array(self):
        j=json.loads((ROOT/"versions/7.1.0-global/analyses/progression/world/"
              "7.1-original-metadata-usage-native-kind-array-writes.json").read_text(encoding="utf-8"))
        self.assertEqual(j["originalExecutableSha256"],s.PROFILE_71.exe_sha256)
        self.assertEqual(j["originalMetadataSha256"],s.PROFILE_71.metadata_sha256)
        self.assertEqual(j["originalMethodMetadataGitBlob"],s.METHODS_BLOB)
        self.assertEqual(j["originalNativeArtifactId"],12416662625)
        method=j["nativeInitializer"]
        self.assertIsNone(method["generatedMethodPredecessorRva"])
        self.assertEqual(method["originalEntryRva"],"0x523400")
        self.assertEqual(method["sourceNativeWindowSizeBytes"],0x3000)
        self.assertEqual(method["sourceNativeWindowSha256"],
                         "d0157c1fab8626c3b28e880e600913841b57d898bef7c5033a7ecff74f30813e")
        self.assertEqual(method["nativeInstructionsDecoded"],287)
        kind=method["nativeKindDispatch"]
        self.assertEqual([x["originalNumericKind"] for x in kind],list(range(8)))
        self.assertEqual([x["originalNativeJumpTargetRva"] for x in kind],
                         ["0x5235F0","0x52362D","0x5234D0","0x52355D",
                          "0x52365C","0x5236FC","0x52355D","0x5237C4"])
        self.assertEqual([x["nativeRegistrationPointerArrayMemberOffsetCandidate"] for x in kind],
                         ["0x50","0x30",None,"0x10","0x20","0x60","0x10","0x58"])
        controls=method["sourceKeyInstructions"]
        by_addr={x["rva"]:x for block in controls.values() for x in block}
        self.assertEqual(by_addr["0x523653"]["operands"],
                         "rcx, qword ptr [rcx + 0x30]")
        self.assertEqual(by_addr["0x5234C0"]["operands"],
                         "qword ptr [rcx + rsi*8], rax")
        self.assertEqual(by_addr["0x523647"]["operands"],"0x140524e80")
        self.assertEqual(by_addr["0x523536"]["operands"],"ebx, 7")
        mapping=j["authenticatedSourceNativeRelationships"]
        self.assertEqual(mapping["sourceNativeKind1RuntimeArrayMemberOffset"],"0x30")
        self.assertEqual(mapping["sourceNativeKind1CreationTargetRva"],"0x524E80")
        self.assertFalse(mapping["nativeSourceKind1TargetClassIdentityProven"])
        self.assertFalse(j["unproven"]["originalNativeFactoryCase1ConcreteTypeDefinitionIndex"])
        self.assertFalse(j["unproven"]["originalScenePointResourceLoaderToThisElementReader"])

if __name__=="__main__":unittest.main()
