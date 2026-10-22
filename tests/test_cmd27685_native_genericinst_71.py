"""Pinned original Global 7.1 native genericinst probe gates."""
from importlib import util
from pathlib import Path
import hashlib
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=util.spec_from_file_location("native_collector_inst",ROOT/"scripts/probe-7.1-cmd27685-native-genericinst.py")
m=util.module_from_spec(spec)
spec.loader.exec_module(m)


class NativeCollectorGenericinst(unittest.TestCase):
    def test_target_original_metadata(self):
        self.assertEqual(m.TYPES["collectorGenericinst"],(24767,"JLDCJCKHJEM","AFGKAIPDLOH",484299))
        self.assertEqual(m.TYPES["messageRepeatedGenericinst"],(65670,"KIIKIELOHOG","GEPFILACKKP",547328))
        self.assertEqual(m.PROFILE_71.exe_sha256,"08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d")

    def test_git_blob_guard(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/"metadata.csv"
            p.write_bytes(b"test")
            self.assertEqual(m.git_blob(p),hashlib.sha1(b"blob 4"+bytes([0])+b"test").hexdigest())
            with self.assertRaisesRegex(ValueError,"SHA-1 mismatch"):
                m.scan_fields(p)


if __name__=="__main__":
    unittest.main()
