"""Exact original Global 7.1 raw type-record numeric 17/18 native control."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
PATH=ROOT/"scripts/probe-7.1-original-type-def-kind-17-18-native.py"
spec=importlib.util.spec_from_file_location("native_type_17_18",PATH)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Original71NativeTypes17And18(unittest.TestCase):
    def test_exact_original_type_record_branches(self):
        j=m.source_prior(ROOT/m.PRIOR)
        self.assertEqual(j["originalGlobal71ExeSha256"],m.PROFILE_71.exe_sha256)
        self.assertEqual(j["originalNativeTypeRecordResolver"]["sourceWindowSha256"],m.RESOLVER_SHA)
        self.assertEqual(m.COMMON_BRANCH,0x50D9EA)
        self.assertEqual(m.TAIL_JUMP,0x50D9F2)
        self.assertEqual(m.TYPEDEF_NATIVE_RVA,0x51CD50)
        self.assertEqual(m.SOURCE_RUNTIME_INDEXES,(0,1,405772,683573))
        self.assertEqual(m.EXPECTED_TYPE_ARRAY_RVA,0x2E1EA20)

    def test_unproven_prior_rejected(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as path:
            fake=Path(path)/"j.json"
            fake.write_text(json.dumps({"originalGlobal71ExeSha256":"not source"}),encoding="utf-8")
            with self.assertRaises(KeyError):
                m.source_prior(fake)



    def test_exact_source_native_record_to_type_def_and_protected_thunk(self):
        report=(ROOT/"versions/7.1.0-global/analyses/progression/world/"
                "7.1-original-type-record-17-18-native-typedef-thunk.json")
        j=json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(j["exactOriginalExeSha256"],m.PROFILE_71.exe_sha256)
        self.assertEqual(j["exactOriginalMetadataSha256"],m.PROFILE_71.metadata_sha256)
        self.assertEqual(j["sourceArchiveArtifactId"],12423519930)
        source=j["originalTypeRecordKindDispatch"]
        self.assertEqual(source["rawNumericTypeKinds"],[17,18])
        self.assertEqual(source["sharedOriginalBranchRva"],"0x50D9EA")
        self.assertEqual(source["sourceDirectRawRecordFieldReadRva"],"0x50D9EA")
        self.assertEqual(source["originalDwordAtOffsetZero"],"dword ptr [rdi]")
        code={x["rva"]:x["operands"] for x in source["originalVerifiedNativeInstructions"]}
        self.assertEqual(code["0x50D9EA"],"ecx, dword ptr [rdi]")
        self.assertEqual(code["0x50D9F2"],"0x14051cd50")
        thunk=j["redirectedOriginalTypeIndexResolver"]
        self.assertEqual(thunk["originalStubRva"],"0x51CD50")
        self.assertEqual(thunk["sourceOriginalJumpOpcodeHex"],"e927159919")
        self.assertEqual(thunk["nativeActualTargetRva"],"0x19EAE27C")
        self.assertEqual(thunk["originalTargetSourceSha256"],
                         "bd346be23bfad674366f0fd6fb33b383286e191fc9ded9c5e52d5ece1ae88211")
        self.assertEqual(thunk["originalJumpTargetNativePrefix"][0]["mnemonic"],"push")
        self.assertFalse(thunk["sourceConcreteClassTypeDefinitionIndexFromProtectedTargetProven"])
        origin=j["originalRuntimeTypeArray"]
        self.assertEqual(origin["sourceRuntimeTypeCount"],683574)
        self.assertEqual(origin["mandatoryOriginalAnchorTypeIndex"],405772)
        self.assertEqual(origin["anchorNativeRawKind"],"0x12")
        self.assertEqual(origin["anchorOriginalTypeDefinitionIndex"],84249)
        self.assertEqual(origin["anchorOriginalObfuscatedName"],"DMMJNICDOHM")
        self.assertEqual(origin["originalIl2CppType16ByteRecords"][2]["sourceOriginalNative16ByteRecordHex"],
                         "19490100000000000000120000000000")
        for val in j["unresolved"].values():
            self.assertFalse(val)

if __name__=="__main__":
    unittest.main()
