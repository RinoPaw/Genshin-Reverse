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

    def test_published_native_genericinst_samples_have_no_unsupported_args(self):
        import json
        file=ROOT/"versions/7.1.0-global/analyses/progression/economy/7.1-cmd27685-native-collector-genericinst.json"
        data=json.loads(file.read_text(encoding="utf-8"))
        self.assertEqual(data["originalExeSha256"],m.PROFILE_71.exe_sha256)
        self.assertEqual(data["originalFieldsGitBlob"],m.FIELDS_BLOB)
        field=data["fields"]["collectorGenericinst"]
        self.assertEqual(field["originalNativeTypeEntryHex"],"72830000000000000100150000000000")
        self.assertEqual(field["nativeTypeDataLowU32"],"0x8372")
        self.assertFalse(field["rawDataPointerFileBacked"])
        self.assertFalse(field["genericClassIndexVerified"])
        self.assertFalse(field["genericKeyTypeVerified"])
        self.assertFalse(field["genericValueTypeVerified"])
        second=data["fields"]["messageRepeatedGenericinst"]
        self.assertEqual(second["originalNativeTypeEntryHex"],"15570200000000002100150000000000")
        self.assertEqual(second["nativeTypeDataLowU32"],"0x25715")
        self.assertFalse(second["rawDataPointerFileBacked"])

    def test_git_blob_guard(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/"metadata.csv"
            p.write_bytes(b"test")
            self.assertEqual(m.git_blob(p),hashlib.sha1(b"blob 4"+bytes([0])+b"test").hexdigest())
            with self.assertRaisesRegex(ValueError,"SHA-1 mismatch"):
                m.scan_fields(p)


if __name__=="__main__":
    unittest.main()
