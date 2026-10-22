"""Original 7.1 internal metadata usage kind-1 native helper source guards."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts/probe-7.1-metadata-kind1-helper-native.py"
spec=importlib.util.spec_from_file_location("native_kind1_71",SCRIPT)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class ExactGlobal71InternalKind1(unittest.TestCase):
    def test_original_source_call_link(self):
        p=m.validate_prior(ROOT/m.PRIOR)
        self.assertEqual(p["originalExecutableSha256"],m.PROFILE_71.exe_sha256)
        self.assertEqual(m.HELPER_RVA,0x524E80)
        self.assertEqual(m.BOUND_RVA,0x525D40)
        self.assertEqual(m.WINDOW,0xEC0)
        self.assertEqual(p["authenticatedSourceNativeRelationships"]["sourceNativeKind1RuntimeArrayMemberOffset"],"0x30")

    def test_prerequisite_drift_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            bogus=Path(td)/"prior.json"
            bogus.write_text(json.dumps({"originalExecutableSha256":"wrong"}),encoding="utf-8")
            with self.assertRaises(KeyError):
                m.validate_prior(bogus)

if __name__=="__main__":unittest.main()
