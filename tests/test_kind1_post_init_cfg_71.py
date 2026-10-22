"""Original Global 7.1 IL2CPP post-resolution native CFG tests."""
from __future__ import annotations
from pathlib import Path
import importlib.util
import json
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts/probe-7.1-kind1-post-init-cfg.py"
sp=importlib.util.spec_from_file_location("nativekindpost71",SCRIPT)
p=importlib.util.module_from_spec(sp)
sp.loader.exec_module(p)


class NativePostTypeResolutionCFGTests(unittest.TestCase):
    def test_verified_prior_source_prefix(self):
        source=json.loads((ROOT/p.PRIOR).read_text(encoding="utf-8"))
        self.assertEqual(source["originalGlobal71ExeSha256"],p.PROFILE_71.exe_sha256)
        self.assertEqual(source["originalPostResolutionClassInit"]["sourceWindowSha256"],
                         p.ORIGINAL_PREFIX_SHA)
        self.assertEqual(source["originalPostResolutionClassInit"]["sourceBoundedWindowBytes"],
                         p.PREFIX_BYTES)
        self.assertEqual(source["sourceNativeHelper"]["originalRuntimePostResolutionInitRva"],
                         f"0x{p.ROOT:X}")

    @unittest.skipUnless(importlib.util.find_spec("capstone"), "Capstone is an optional native research dependency")
    def test_reachable_native_branches_do_not_execute_call_bodies(self):
        # 75 05: JNE +5 => address +7; E8 00..00: CALL +7; C3: RET
        # Both branches reach one RET. No call-body traversal or inline data.
        code=b"\x75\x05\xE8\x00\x00\x00\x00\xC3"+b"\xCC"*(p.PREFIX_BYTES-8)
        report=p.inspect_control_flow(code,0x140000000,start_rva=p.ROOT)
        self.assertEqual(report["reachableDecodedOriginalInstructions"],3)
        self.assertEqual(report["returnCount"],1)
        self.assertEqual(report["directCallCount"],1)
        self.assertEqual(report["directCalls"][0]["targetRva"],f"0x{p.ROOT+7:X}")
        self.assertEqual(report["unresolvedNativeBranchOrDecodeCount"],0)
        self.assertTrue(report["verifiedCompleteWithinWindow"])

    @unittest.skipUnless(importlib.util.find_spec("capstone"), "Capstone is an optional native research dependency")
    def test_unresolved_native_indirect_jump_kept(self):
        code=b"\xFF\xE0"+b"\xCC"*(p.PREFIX_BYTES-2) # jmp rax
        result=p.inspect_control_flow(code,0x140000000,start_rva=p.ROOT)
        self.assertEqual(result["returnCount"],0)
        self.assertEqual(result["unresolvedNativeBranchOrDecodeCount"],1)
        self.assertFalse(result["verifiedCompleteWithinWindow"])


    def test_retained_exact_native_cfg_run_evidence(self):
        pth=(ROOT/"versions/7.1.0-global/analyses/progression/world/"
              "7.1-original-kind1-post-resolution-init-reachable-cfg.json")
        r=json.loads(pth.read_text(encoding="utf-8"))
        self.assertEqual(r["originalExeSha256"],p.PROFILE_71.exe_sha256)
        self.assertEqual(r["originalMetadataSha256"],p.PROFILE_71.metadata_sha256)
        self.assertEqual(r["originalArtifactId"],12422281142)
        self.assertEqual(r["originalSourceFirst0x380BytesSha256"],p.ORIGINAL_PREFIX_SHA)
        self.assertEqual(r["originalVerifiedSourceWindowByteCount"],p.MAX_WINDOW)
        self.assertEqual(r["originalVerifiedSourceWindowSha256"],
                         "a57557282472d178ec609a7772efe5f448eee23348be89a26c803382fca03af1")
        self.assertEqual(r["sourceReachableDecodedInstructions"],1279)
        self.assertEqual(len(r["originalReachableReturnSites"]),1)
        self.assertEqual(r["originalReachableReturnSites"][0]["rva"],"0x513DE0")
        self.assertEqual(r["originalNativeDirectCallCount"],57)
        self.assertEqual(r["originalNativeIndirectCallCount"],8)
        self.assertEqual(r["originalSourceUnresolvedJumpOrDecodeCount"],0)
        self.assertEqual(r["sourceNativeTargetsOfInterest"]["sourceDirectRecursiveSelfCalls"],4)
        self.assertEqual(r["sourceNativeTargetsOfInterest"]["sourceDirectRuntimeTypeResolverCalls"],2)
        self.assertTrue(r["claims"]["sourcePostResolutionNativeEntryReachableReturnLocated"])
        self.assertTrue(r["claims"]["sourceNativeForwardAndConditionalJumpEdgesWithinWindowResolved"])
        for x in ("sourceOriginalConcreteFactoryCase1TypeResolved",
                  "sourceOriginalConcreteFactoryCase14TypeResolved",
                  "scenePointResourcePathToReaderLinkResolved",
                  "originalChestGadgetPlacementCoordinatesAndLevelProven",
                  "serverClientPlacementAuthorityProven"):
            self.assertFalse(r["claims"][x])

if __name__=="__main__":
    unittest.main()
