"""Verify exact original 7.1 array element dispatch evidence boundaries."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
FILE=ROOT/"scripts/probe-7.1-scene-point-array-element-native.py"
spec=importlib.util.spec_from_file_location("array_element_71",FILE)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Original71ArrayElementEvidence(unittest.TestCase):
    def test_original_native_source_anchors(self):
        p=json.loads((ROOT/m.PRIOR).read_text(encoding="utf-8"))
        self.assertEqual(p["originalExeSha256"],m.PROFILE_71.exe_sha256)
        self.assertTrue(p["originalNativeConditionalReadProof"]["sourceNativeHelperConsumesExactlyOneByteFor0xCB"])
        self.assertEqual(m.RVA,0xAD23000)
        self.assertEqual(m.INDIRECT_RVA,0xAD230BB)
        self.assertEqual(m.SOURCE_SHA,"6319613278adf382bf7ce513d1d875ef98b318d5f5f3bc9c423b72caebd7c0ad")

    def test_original_git_blob_is_required(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"methods.csv"
            p.write_text("type_name,method_name\nNLDEPJEOJGC,GMENPOPMKAA\n",encoding="utf-8")
            with patch.object(m,"git_blob",return_value="invalid"):
                with self.assertRaisesRegex(ValueError,"metadata Git blob drift"):
                    m.metadata_members(p,"method")

if __name__=="__main__":
    unittest.main()
