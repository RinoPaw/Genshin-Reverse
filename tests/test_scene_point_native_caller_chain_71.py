"""Source and uncertainty boundary tests for original 7.1 array reader callers."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
S=ROOT/"scripts/probe-7.1-scene-point-native-caller-chain.py"
spec=importlib.util.spec_from_file_location("pointcaller71",S)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
PRIOR=ROOT/m.PRIOR_SCENE_POINT

class ScenePointNativeCallerTests(unittest.TestCase):
    def test_original_callee_identity(self):
        j=json.loads(PRIOR.read_text(encoding="utf-8"))
        n=j["sourceNativeArrayCountReader"]
        self.assertEqual(m.TARGET,0xAD23000)
        self.assertEqual(n["originalMethodRva"],f"0x{m.TARGET:X}")
        self.assertEqual(n["originalMethodIndex"],m.METHOD_INDEX)
        self.assertEqual(n["originalMethodWindowSha256"],m.SOURCE_WINDOW_SHA)
        self.assertTrue(n["genericNativeU32XorCountReaderProven"])
        self.assertFalse(n["originalScenePointLoaderCallsThisReaderProven"])

    def test_method_index_must_match_original_source(self):
        j=json.loads(PRIOR.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            csvpath=Path(tmp)/"methods.csv"
            csvpath.write_text("rva,type_name,type_definition_index,method_name,method_index,parameter_types\n"
                 "0xAD23000,NLDEPJEOJGC,63768,GMENPOPMKAA,514423,[]\n"
                 "0xAD23010,other,1,foo,3,[]\n",encoding="utf-8")
            with patch.object(m,"git_blob",return_value=m.METHODS_GIT_BLOB):
                starts,rows=m.validate_source(csvpath,PRIOR)
                self.assertEqual(starts[0],m.TARGET)
                self.assertEqual(rows[m.TARGET][0]["method_name"],m.METHOD)
            with patch.object(m,"git_blob",return_value="source drift"):
                with self.assertRaisesRegex(ValueError,"Git-blob mismatch"):
                    m.validate_source(csvpath,PRIOR)

    def test_wrong_source_reader_rejected(self):
        j=json.loads(PRIOR.read_text(encoding="utf-8"))
        self.assertEqual(j["originalExeSha256"],m.PROFILE_71.exe_sha256)
        self.assertEqual(j["originalMethodsGitBlob"],m.METHODS_GIT_BLOB)

if __name__=="__main__":
    unittest.main()
