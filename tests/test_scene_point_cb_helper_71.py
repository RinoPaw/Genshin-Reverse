"""Guard original 7.1 Scene Point-compatible 0xCB helper native source."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts/probe-7.1-scene-point-cb-native-branch.py"
spec=importlib.util.spec_from_file_location("scene_cb71",SCRIPT)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class SourceNativeCB(unittest.TestCase):
    def test_authenticated_precursor_identity(self):
        p=json.loads((ROOT/m.PRIOR).read_text(encoding="utf-8"))
        self.assertEqual(p["originalExeSha256"],m.PROFILE_71.exe_sha256)
        self.assertEqual(p["nativeIntermediateReader"]["nativeWindowSha256"],m.PREFIX_SHA)
        self.assertEqual(m.RVA,0x12498FE0)
        self.assertEqual(m.INDEX,173227)
        self.assertEqual(m.OWNER,"CCPCOHEPGHC")

    def test_thirteen_scene_point_prefixes_share_cb(self):
        s=json.loads((ROOT/m.SCENES).read_text(encoding="utf-8"))
        self.assertEqual(s["scenesChecked"],13)
        self.assertEqual({bytes.fromhex(x["unwrappedPayloadFirst32Hex"])[2]
                          for x in s["assetRows"]},{0xCB})
        self.assertEqual(0xCB&0x10,0)

    def test_original_method_csv_git_blob_is_mandatory(self):
        with tempfile.TemporaryDirectory() as td:
            bad=Path(td)/"methods.csv"
            bad.write_text("type_definition_index,type_name,method_name,method_index,rva\n",
                           encoding="utf-8")
            with patch.object(m,"blob_sha",return_value="wrong"):
                with self.assertRaisesRegex(ValueError,"blob drift"):
                    m.source_guards(bad,ROOT/m.PRIOR,ROOT/m.SCENES)


    def test_source_verified_native_cb_single_byte_path(self):
        evidence=(ROOT/"versions/7.1.0-global/analyses/progression/world/"
                  "7.1-original-scene-point-cb-one-byte-native-proof.json")
        j=json.loads(evidence.read_text(encoding="utf-8"))
        self.assertEqual(j["originalExeSha256"],m.PROFILE_71.exe_sha256)
        self.assertEqual(j["originalMethodsGitBlob"],m.METHODS_SHA)
        self.assertEqual(j["sourceArtifactId"],12408788938)
        self.assertEqual(j["nativeMethodRva"],f"0x{m.RVA:X}")
        self.assertEqual(j["sourceMethodSha256"],
                         "5460efab0d1bd47142105a15f34b7513a1e65944c71f5f3d7d290bddceb536b3")
        self.assertEqual(j["nativeMethodBytes"],1984)
        self.assertEqual(j["originalDisassembledInstructions"],467)
        b=j["originalNativeConditionalReadProof"]
        self.assertTrue(b["sourceNativeHelperConsumesExactlyOneByteFor0xCB"])
        self.assertEqual(b["xoredFlagByte"],"0x00")
        self.assertEqual(b["nativeConditionalBranchesVerified"],5)
        self.assertEqual(len(b["sourceBlocks"]),6)
        self.assertEqual(b["nativeStreamByteReadsAlongPath"],1)
        self.assertEqual(b["nativeStreamCursorWritesAlongPath"],1)
        self.assertEqual(b["nativeHelperCallsAlongPath"],0)
        self.assertEqual(b["sourceReturnRva"],"0x124995FF")
        for i,block in enumerate(b["sourceBlocks"]):
            self.assertEqual(int(block["firstRva"],16),m.CB_BASIC_BLOCKS[i][0])
            self.assertEqual(int(block["lastRva"],16),m.CB_BASIC_BLOCKS[i][1])
        self.assertFalse(j["originalParentReceivesSourceScenePointBytesAtOffsetZeroProven"])
        self.assertFalse(j["originalArrayReaderStartsAtPayloadOffsetThreeWithoutAssumptionsProven"])
        self.assertFalse(j["originalScenePointRowsDecoded"])
        self.assertFalse(j["originalChestGadgetInstancePositionsDecoded"])

    def test_source_verified_native_cb_path_rejects_drift(self):
        evidence=(ROOT/"versions/7.1.0-global/analyses/progression/world/"
                  "7.1-original-scene-point-cb-one-byte-native-proof.json")
        j=json.loads(evidence.read_text(encoding="utf-8"))
        ins=[x for block in j["originalNativeConditionalReadProof"]["sourceBlocks"]
             for x in block["sourceNativeInstructions"]]
        self.assertEqual(len(ins),len({x["rva"] for x in ins}))
        proof=m.prove_single_byte_cb_route(ins,0x140000000)
        self.assertTrue(proof["sourceNativeHelperConsumesExactlyOneByteFor0xCB"])
        mutated=[dict(x) for x in ins]
        ix=next(i for i,x in enumerate(mutated) if x["rva"]=="0x124994DC")
        mutated[ix]["op"]="test r13b, 2"
        with self.assertRaisesRegex(ValueError,"witness mismatch"):
            m.prove_single_byte_cb_route(mutated,0x140000000)

if __name__=="__main__":
    unittest.main()
