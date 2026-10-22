"""Original CmdId27685 exact class/native field-offset probe constraints."""
from importlib import util
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=util.spec_from_file_location("cmd27685_field",ROOT/"scripts/probe-7.1-cmd27685-element-field-offset.py")
m=util.module_from_spec(spec)
spec.loader.exec_module(m)

class ExactCandidateScope(unittest.TestCase):
    def test_native_and_metadata_identities(self):
        self.assertEqual(m.XREF_SLOT,0x57D1928)
        self.assertEqual(m.METHODS["elementReader"][0:4],
                         (705939,"KFOLLNPEMHH","NLGBJEEJDLG",0xB43A2A0))
        self.assertEqual(m.METHODS["collectionConsumer"][3],0xFCDF5D0)
        self.assertEqual(set(m.POSITIVE_NATIVE),{"containerCopyFrom","containerReader"})

    def test_bad_original_metadata_gate(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as td:
            p=Path(td)/"file"
            p.write_bytes(b"unverified")
            with self.assertRaisesRegex(ValueError,"different original"):
                m.native_metadata_control(p,p)
if __name__=="__main__":unittest.main()
