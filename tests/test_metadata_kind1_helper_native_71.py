"""Original 7.1 internal metadata usage kind-1 native helper source guards."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts/probe-7.1-metadata-kind1-helper-native.py"
spec=importlib.util.spec_from_file_location("native_kind1_71",SCRIPT)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class ExactGlobal71InternalKind1(unittest.TestCase):
    def test_original_source_call_link(self):
        p=m.validate_prior(ROOT/m.PRIOR)
        self.assertEqual(p["originalExecutableSha256"],m.PROFILE_71.exe_sha256)
        self.assertEqual(m.HELPER_RVA,0x524E80)
        self.assertEqual(m.BOUND_RVA,0x525D40)
        self.assertEqual(m.WINDOW,0xEC0)
        self.assertEqual(p["authenticatedSourceNativeRelationships"]["sourceNativeKind1RuntimeArrayMemberOffset"],"0x30")

    def test_prerequisite_drift_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            bogus=Path(td)/"prior.json"
            bogus.write_text(json.dumps({"originalExecutableSha256":"wrong"}),encoding="utf-8")
            with self.assertRaises(KeyError):
                m.validate_prior(bogus)


    def test_original_source_type_index_cache_and_native_kind_30_case_dispatch(self):
        file=(ROOT/"versions/7.1.0-global/analyses/progression/world/"
              "7.1-original-metadata-kind1-type-resolver-30-case-native.json")
        j=json.loads(file.read_text(encoding="utf-8"))
        self.assertEqual(j["originalGlobal71ExeSha256"],m.PROFILE_71.exe_sha256)
        self.assertEqual(j["originalMetadataSha256"],m.PROFILE_71.metadata_sha256)
        self.assertEqual(j["sourceOriginalArtifactId"],12418629172)
        core=j["sourceNativeHelper"]
        self.assertEqual(core["sourceCoreSha256"],
                         "0bf64afba538ed8bf9d3e482c240b5a6bdab2502c200c1cf3af8448a3ad649be")
        self.assertEqual(core["coreFlowByteLength"],0xB0)
        self.assertEqual(core["cacheGlobalSlotRva"],"0x5AD52D0")
        self.assertEqual(core["cacheEntryStrideBytes"],8)
        self.assertEqual(core["originalMetadataRegistrationGlobalSlotRva"],"0x5AD52A0")
        self.assertEqual(core["originalMetadataTypeRecordPointerMemberOffset"],"0x48")
        self.assertEqual(core["originalMetadataRecordStrideBytes"],16)
        self.assertEqual(core["originalRuntimeTypeObjectResolverRva"],"0x50D9C0")
        self.assertEqual(core["originalRuntimePostResolutionInitRva"],"0x512DB0")
        self.assertEqual(core["primaryReturnRva"],"0x524F1E")
        witnesses={x["rva"]:x["operands"] for x in core["sourceOriginalNativeInstructionWitnesses"]}
        self.assertEqual(witnesses["0x524E94"],"ecx, -1")
        self.assertEqual(witnesses["0x524EA3"],"rsi, qword ptr [rax + rdi*8]")
        self.assertEqual(witnesses["0x524EB6"],"rcx, 4")
        self.assertEqual(witnesses["0x524EBA"],"rcx, qword ptr [rax + 0x48]")
        self.assertEqual(witnesses["0x524F0C"],"qword ptr [rax + rdi*8], rsi")
        sub=j["originalNativeTypeRecordResolver"]
        self.assertEqual(sub["sourceWindowSha256"],
                         "83347d5b374e29f40e0b35ff2e99bb69b387d1d57286d953ccf7a39b982c971b")
        self.assertEqual(sub["sourceRecordKindSignedByteOffset"],"0xA")
        self.assertEqual(sub["originalRawKindRangeInclusive"],[1,30])
        self.assertEqual(sub["sourceJumpTableRva"],"0x50DC50")
        self.assertEqual(sub["sourceJumpTableSha256"],
                         "7f53e8e45d3580d527fce4997702b6daffa676e614c0e96cc86c4a0f03c7077d")
        self.assertEqual([x["rawNumericKind"] for x in sub["originalKindJumpTableTargets"]],
                         list(range(1,31)))
        self.assertTrue(all(x["sourceInstructionBoundaryAuthenticated"] for x in sub["originalKindJumpTableTargets"]))
        self.assertFalse(sub["concreteFactoryCase1Or14TypeMapped"])
        self.assertFalse(sub["exactSourceOriginalTagSemanticNamesProven"])
        self.assertEqual(j["originalPostResolutionClassInit"]["sourceWindowSha256"],
                         "ed5bd32a72c08bfd40f2627bbfe49d22a9104bd77941ec4980107f514cd43cc1")
        for claim in j["unknown"].values():
            self.assertFalse(claim)

if __name__=="__main__":unittest.main()
