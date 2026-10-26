"""Regression for original Global 7.1 input-string and ZIP data loader native edges."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
REPORT=ROOT/"versions/7.1.0-global/analyses/progression/world/7.1-original-scene-parent-string-and-zip-loader-native-callees.json"
PRIOR=ROOT/"versions/7.1.0-global/analyses/progression/world/7.1-original-scene-parent-native-pre-input-callees.json"
SCRIPT=ROOT/"scripts/probe-7.1-point-parent-loader-callees.py"
spec=importlib.util.spec_from_file_location("probe_original71_source_zip_loader",SCRIPT)
probe=importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class OriginalScenePointZipLoaderNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p=json.loads(REPORT.read_text(encoding="utf-8"))
        cls.methods=cls.p["sourceOriginalCalleePaths"]

    def test_exact_original_client_identity_and_source_proof(self):
        p=self.p
        self.assertEqual(p["originalExeSha256"],probe.PROFILE_71.exe_sha256)
        self.assertEqual(p["originalMetadataSha256"],probe.PROFILE_71.metadata_sha256)
        self.assertEqual(p["originalMethodsGitBlob"],
            "a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a")
        self.assertEqual(len(probe.extract_prior(PRIOR)),3)
        self.assertEqual(len(self.methods),len(probe.CALLEES))
        self.assertEqual(p["sourceOriginalArchiveArtifactId"],12637056030)
        self.assertEqual(p["sourceOriginalRunHeadSha"],"25a50bf49237e2fec7fc89a0f6541f3d9586ee8b")
        self.assertEqual(p["sourceOriginalRunUrl"],
            "https://github.com/RinoPaw/Genshin-Reverse/actions/runs/40292990195")
        self.assertEqual(p["sourceOriginalArchiveArtifactDigest"],
            "sha256:bb200e824e40c78430ac55c3be58ce041c31fcd598d1f7600db9e19516bdcbf5")

    def test_original_string_assembly_exact_native_declarations(self):
        expected={
          "string_hash_parameter_builder":("NumberFormatInfo","get_CurrentInfo",6770,"0x194AED40","c1be42b318b2b61ac728c381c29529864fbc6506e20b88a1401e53f5c0bdb993"),
          "string_key_formatter":("NumberFormatter","NumberToString",3829,"0x195F34B0","75bbd58c7c253d5b330a8ba93d498fe7eb61263a4a6d2cabae59f259b4a24f00"),
          "string_fast_tail":("String","Concat",3019,"0x194675B0","b78fffb0cca2daf1e8f81523c87ca2827e452755e88ac4f1e29fbb86622b43e6"),
          "string_fallback_tail":("ILFixDynamicMethodWrapper","__Gen_Wrap_30",587358,"0xD8E1CB0","11b38d53976f731662f0c2f088b7701fb29958dc568494b9db50ffdb59726a09")
        }
        for name,(owner,method,index,rva,sha) in expected.items():
            with self.subTest(target=name):
                x=self.methods[name]
                self.assertEqual(x["sourceExactTargetRva"],rva)
                self.assertTrue(x["sourceTargetIsOriginalDeclaredMethodStart"])
                self.assertEqual(x["sourceNativeProbeSha256"],sha)
                self.assertEqual(len(x["sourceExactMetadataMethodOwner"]),1)
                o=x["sourceExactMetadataMethodOwner"][0]
                self.assertEqual((o["originalTypeName"],o["originalMethodName"],o["originalMethodIndex"]),
                                 (owner,method,index))
        self.assertEqual(self.methods["string_key_formatter"]["sourceExactMetadataMethodOwner"][0]["originalParameterTypes"],
                         '["string","uint32","IFormatProvider"]')
        self.assertEqual(self.methods["string_fast_tail"]["sourceExactMetadataMethodOwner"][0]["originalParameterTypes"],
                         '["string","string","string"]')

    def test_original_zip_loader_declared_and_native_handoff(self):
        x=self.methods["record_get_bytes"]
        self.assertEqual(x["sourceOriginalProducerMethodRva"],"0x1016E3F0")
        self.assertEqual(x["sourceOriginalInstructionSite"],"0x1016E4AC")
        self.assertEqual(x["sourceOriginalInstructionBytes"],"e8afeac1f6")
        self.assertEqual(x["sourceExactTargetRva"],"0x6D8CF60")
        self.assertEqual(x["sourceNativeProbeBytes"],656)
        self.assertEqual(x["sourceNativeProbeSha256"],
                         "af4b34d807feb189c183574127598bdd1a1066d0536f2a199fff05b14807fcbd")
        o=x["sourceExactMetadataMethodOwner"][0]
        self.assertEqual(o["originalTypeName"],"CommonMiscs")
        self.assertEqual(o["originalMethodName"],"LoadBinDataZipFile")
        self.assertEqual(o["originalMethodIndex"],79876)
        self.assertEqual(o["originalTypeDefinitionIndex"],11251)
        self.assertEqual(o["originalParameterTypes"],
                         '["uint64","int32","int32","CompressionType","int32"]')

    def test_original_native_helper_and_uncertainty(self):
        x=self.methods["record_open_first"]
        self.assertFalse(x["sourceTargetIsOriginalDeclaredMethodStart"])
        self.assertEqual(x["sourceExactTargetRva"],"0x1475C1D0")
        self.assertEqual([z["rva"] for z in x["sourceIndirectCallInstructions"]],
                         ["0x1475C2D7","0x1475C3BB"])
        for k in ("originalScenePoint13IndexedAssetsConnectedToNativeLoader",
                  "originalWorldChestPlacementOrInstanceLevelProven"):
            self.assertFalse(self.p[k])


if __name__=="__main__":
    unittest.main()
