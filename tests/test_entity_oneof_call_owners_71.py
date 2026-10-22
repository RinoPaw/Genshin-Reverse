"""Original 7.1 native oneof and exact-RVA ownership tests."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
S=ROOT/"scripts/probe-7.1-entity-oneof-call-owners.py"
spec=importlib.util.spec_from_file_location("nativeoneof71",S)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
PRIOR=ROOT/"versions/7.1.0-global/analyses/progression/economy/7.1-original-scene-entity-float-parent-native-chain.json"

class OriginalOneofNativeTests(unittest.TestCase):
    def test_original_pinned_source(self):
        prior=json.loads(PRIOR.read_text(encoding="utf-8"))
        self.assertEqual(prior["parentReader"]["sourceSha256"],m.PARENT_HASH)
        self.assertEqual(prior["additionalNativeMethods"]["elementCopyFrom"]["originalWindowSha256"],m.COPY_HASH)
        self.assertEqual(prior["additionalNativeMethods"]["elementStaticInitializer"]["originalWindowSha256"],m.STATIC_HASH)
        self.assertEqual(m.ELEMENT,"KFOLLNPEMHH")
        self.assertEqual(m.CHILD,"ABOOLMJBDKE")
        self.assertEqual(m.CHILD_READER_RVA,0x11B25D70)

    def test_tag_and_discriminator_anchors(self):
        rows=[
            {"rva":"0xB43A522","mnemonic":"cmp","op":"eax, 0x52","bytes":"83f852"},
            {"rva":"0xB43A52B","mnemonic":"cmp","op":"eax, 0x5a","bytes":"83f85a"},
            {"rva":"0xB43A534","mnemonic":"cmp","op":"eax, 0x62","bytes":"83f862"},
            {"rva":"0xB43A366","mnemonic":"cmp","op":"eax, 0x6a","bytes":"83f86a"},
            *[{"rva":f"0x{0xB43A55C+i:X}","mnemonic":"cmp",
                "op":f"dword ptr [r12 + 0x94], {value:#x}",
                "bytes":"83f8"+f"{value:02x}"} for i,value in enumerate(range(10,14))]
        ]
        proto=m.tag_witnesses(rows)
        self.assertEqual({a["wireFieldNumberIfProtoKey"] for a in proto},{10,11,12,13})
        self.assertTrue(all(a["linkedTypedFieldProven"] is False for a in proto))
        disc=m.discriminator_witnesses(rows)
        self.assertEqual({a["discriminatorValue"] for a in disc},{10,11,12,13})

    def test_only_exact_method_rva_owners(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"methods.csv"
            path.write_text("rva,type_name,type_definition_index,method_index,method_name,parameter_types,return_type\n"
                "0xB43A2A0,KFOLLNPEMHH,85506,705939,NLGBJEEJDLG,[],void\n"
                "0xB43A300,FAKE,1,1,Unknown,[],void\n",encoding="utf-8")
            with patch.object(m,"git_blob",return_value=m.METHODS_BLOB):
                x=m.method_lookup(path,{0xB43A2A0,0xB43A300,0xB43A301})
            self.assertNotIn(0xB43A301,x)
            self.assertEqual(x[0xB43A2A0][0]["originalTypeDefinitionIndex"],85506)


    def test_source_verified_original_method_target_evidence(self):
        report_path=(ROOT/"versions/7.1.0-global/analyses/progression/economy/"
           "7.1-original-entity-variant-native-call-owners.json")
        report=json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["originalExeSha256"],m.PROFILE_71.exe_sha256)
        self.assertEqual(report["originalMethodMetadataGitBlob"],m.METHODS_BLOB)
        self.assertEqual(report["originalSource"]["artifactId"],12403764170)
        self.assertEqual(report["verification"]["parentReaderSha256"],m.PARENT_HASH)
        self.assertEqual(report["verification"]["parentCopyFromSha256"],m.COPY_HASH)
        self.assertEqual(report["verification"]["parentStaticInitializerSha256"],m.STATIC_HASH)
        self.assertEqual({x["wireKeyCandidateHex"] for x in
                          report["originalNativeCandidateProtobufTagComparisons"]},
                         {"0x52","0x5A","0x62","0x6A"})
        self.assertEqual({x["v"] for x in
                          report["originalNativeDiscriminatorComparisons"]},
                         {10,11,12,13})
        self.assertEqual(report["windows"]["parentReader"]["decodedInstructionCount"],708)
        self.assertEqual(report["windows"]["parentCopyFrom"]["decodedInstructionCount"],505)
        self.assertEqual(report["windows"]["parentReader"]["exactRvaOwnerMatchedTransfers"],41)
        parent_methods=report["windows"]["parentReader"]["distinctTargetsWithExactMetadata"]
        owners={hit["originalTypeName"] for row in parent_methods
                for hit in row["owners"]}
        self.assertTrue({"KLCICGEAJGM","OFPGGBDNEAP","PIGADKBHAME"}.issubset(owners))
        self.assertEqual(report["exactSourceChildMethodOwners"]["0x11B252C0"][0]["originalTypeName"],m.CHILD)
        self.assertTrue(report["evidenceBoundary"]
                        ["numericTagAndVariantSwitchObservationsSourceVerified"])
        for key in ("originalTypedFieldDLOEKFLGJCGRuntimeOffsetVerified",
                    "originalABOOLMJBDKEIndirectRuntimeDispatchTargetVerified",
                    "originalABOOLMJBDKEFloatMeaningVerified",
                    "originalSceneChestPlacementOriginVerified",
                    "originalServerPacketDirectionVerified"):
            self.assertFalse(report["evidenceBoundary"][key])

if __name__=="__main__":
    unittest.main()
