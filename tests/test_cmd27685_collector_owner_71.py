"""Exact Global 7.1 native collector-owner metadata source gates."""
import importlib.util
from pathlib import Path
import hashlib
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("native_collector",
     ROOT/"scripts/probe-7.1-cmd27685-collector-owner.py")
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class CollectorOwner(unittest.TestCase):
    def test_owner_and_native_offsets(self):
        self.assertEqual(m.ORIGINAL_TYPE,"JLDCJCKHJEM")
        self.assertEqual(m.KNOWN_ONACCEPT,(190174,0xFCDF5D0))

    def test_original_metadata_sha_gate(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"file"
            p.write_bytes(b"test")
            self.assertEqual(m.git_blob(p),
                             hashlib.sha1(b"blob 4"+bytes([0])+b"test").hexdigest())
            with self.assertRaisesRegex(ValueError,"original source metadata"):
                m.collect(p,p)


if __name__=="__main__":
    unittest.main()
