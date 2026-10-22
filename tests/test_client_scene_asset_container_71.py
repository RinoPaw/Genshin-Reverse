"""Original 7.1 sample index and manifest category inventory control tests."""
import importlib.util
from pathlib import Path
import struct
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("scene_inventory",ROOT/"scripts/probe-7.1-client-scene-asset-container.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def strings_pair(a,b):
    return struct.pack("<I",len(a))+a+struct.pack("<I",len(b))+b

class SceneAssetInventory(unittest.TestCase):
    def test_manifest_prefix_counts_and_scene_name_boundaries(self):
        source=[
          {"filename":"GenshinImpact_Data/StreamingAssets/AssetBundles/blocks/00/123.blk","size":10},
          {"filename":"GenshinImpact_Data/StreamingAssets/ScriptSceneData/a.bin","size":20},
          {"filename":"GenshinImpact_Data/Scripts/Scene/test.lua","size":30},
        ]
        result=m.summarize_manifest(source)
        self.assertEqual(result["manifestFileCount"],3)
        self.assertEqual(result["wholeManifestLuaFileCount"],1)
        self.assertEqual(result["wholeManifestSceneFileCount"],2)
        self.assertEqual(result["assetBundleBlockSubdirectories"],{"00":1})
        self.assertTrue(result["pathsContainingRelevantTokens"]["scene"])

    def test_paired_original_asset_type_header(self):
        body=struct.pack("<I",2)+strings_pair(b"MonoBehaviour",b"assembly")+strings_pair(b"TextAsset",b"namespace")
        raw=struct.pack("<I",len(body))+body
        self.assertEqual(m.index_type_header(raw),[
          {"index":0,"firstOriginalName":"MonoBehaviour","secondOriginalName":"assembly"},
          {"index":1,"firstOriginalName":"TextAsset","secondOriginalName":"namespace"},
        ])

    def test_hash_pins_are_fixed(self):
        self.assertEqual(m.MANIFEST_ZSTD_SHA256,"3383e77a832d0076e84b4bd441867c293ccb2eff13e4380a2ef0df5b4d087d66")
        with self.assertRaisesRegex(ValueError,"Sophon compressed manifest"):
            m.audit(b"wrong",b"wrong")
        self.assertEqual(m.INDEX_RAW_SHA256,"fe1e1ce970e3aa72e764b0894d94a684b7a49edc9f3ae6a32c4d7f38d8a64712")
if __name__=="__main__":unittest.main()
