"""Original Global 7.1 metadata usage initializer source boundary guards."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts/probe-7.1-usage-initializer-native.py"
spec=importlib.util.spec_from_file_location("init_native_71",SCRIPT)
s=importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)

class OriginalUsageInitializer(unittest.TestCase):
    def test_original_source_identity(self):
        p=json.loads((ROOT/s.PRIOR).read_text(encoding="utf-8"))
        self.assertEqual(p["originalExecutableSha256"],s.PROFILE_71.exe_sha256)
        self.assertEqual(p["originalMetadataSha256"],s.PROFILE_71.metadata_sha256)
        self.assertEqual(p["sourceOriginalUsageLayout"]["originalCandidateListCount"],311730)
        self.assertEqual(s.INITIALIZER_RVA,0x523400)
        self.assertEqual(s.ROOT_RVA,0x5AD52A8)

    def test_original_method_blob_hash_guard(self):
        with tempfile.TemporaryDirectory() as d:
            bogus=Path(d)/"methods.csv"
            bogus.write_text("not original",encoding="utf-8")
            with patch.object(s,"git_blob",return_value="bad"):
                with self.assertRaisesRegex(ValueError,"methods source drift"):
                    s.inspect(Path("missing"),bogus,ROOT/s.PRIOR)
if __name__=="__main__":unittest.main()
