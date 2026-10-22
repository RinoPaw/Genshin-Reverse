"""Exact original Global 7.1 raw type-record numeric 17/18 native control."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
PATH=ROOT/"scripts/probe-7.1-original-type-def-kind-17-18-native.py"
spec=importlib.util.spec_from_file_location("native_type_17_18",PATH)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Original71NativeTypes17And18(unittest.TestCase):
    def test_exact_original_type_record_branches(self):
        j=m.source_prior(ROOT/m.PRIOR)
        self.assertEqual(j["originalGlobal71ExeSha256"],m.PROFILE_71.exe_sha256)
        self.assertEqual(j["originalNativeTypeRecordResolver"]["sourceWindowSha256"],m.RESOLVER_SHA)
        self.assertEqual(m.COMMON_BRANCH,0x50D9EA)
        self.assertEqual(m.TAIL_JUMP,0x50D9F2)
        self.assertEqual(m.TYPEDEF_NATIVE_RVA,0x51CD50)
        self.assertEqual(m.SOURCE_RUNTIME_INDEXES,(0,1,405772,683573))
        self.assertEqual(m.EXPECTED_TYPE_ARRAY_RVA,0x2E1EA20)

    def test_unproven_prior_rejected(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as path:
            fake=Path(path)/"j.json"
            fake.write_text(json.dumps({"originalGlobal71ExeSha256":"not source"}),encoding="utf-8")
            with self.assertRaises(KeyError):
                m.source_prior(fake)


if __name__=="__main__":
    unittest.main()
