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

if __name__=="__main__":
    unittest.main()
