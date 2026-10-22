"""Verify exact native scene-area AssetBundle class inventory source gates."""
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("native_unity_classes",ROOT/"scripts/probe-7.1-world-area-bundle-object-types.py")
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class NativeUnityObjects(unittest.TestCase):
    def test_source_pinned_positive_control(self):
        self.assertEqual(m.SOURCE_BLOCK_ID,24230448)
        self.assertEqual(m.BLOCK_MD5,"1ad9ee10633cf3154a27f87690b5008f")
        self.assertEqual(m.SCENE3_RAW_SHA,"e66d6ec832bed734e824714d345961715b01edbdce50f6115b07983ec205eda9")
        self.assertEqual(m.CLASS_TYPES,("MiHoYoBinData","TextAsset","MonoBehaviour"))

    def test_types_count_only_actual_exported_files(self):
        with TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/"TextAsset"/"TextAsset").mkdir(parents=True)
            (root/"TextAsset"/"TextAsset"/"SceneTarget.dat").write_bytes(b"ok")
            (root/"MiHoYoBinData"/"MiHoYoBinData").mkdir(parents=True)
            (root/"MiHoYoBinData"/"MiHoYoBinData"/"name.dat").write_bytes(b"test")
            c=m.files_per_type(root)
            self.assertEqual(c["TextAsset"]["totalRawExports"],1)
            self.assertEqual(c["TextAsset"]["filenameMatchCount"],1)
            self.assertEqual(c["MiHoYoBinData"]["totalRawExports"],1)
            self.assertEqual(c["MonoBehaviour"]["totalRawExports"],0)
if __name__=="__main__":unittest.main()
