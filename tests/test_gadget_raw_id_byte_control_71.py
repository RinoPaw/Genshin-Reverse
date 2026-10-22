"""Original 7.1 GadgetExcel source positive decoding independently checks raw-byte heuristic."""
from importlib import util
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=util.spec_from_file_location("raw_gadget_source_control",ROOT/"scripts/control-7.1-gadget-raw-id-byte-scan.py")
mod=util.module_from_spec(spec);spec.loader.exec_module(mod)

class RawIdSourcePositiveControl(unittest.TestCase):
    def test_exact_source_identity(self):
        self.assertEqual(mod.RAW_SHA256,
            "a35e3f3ed04f950cb6302099d12aa71e23ece21d8fe578950347d9318f769e35")
        self.assertEqual(mod.EXPECTED_ROWS,30599)
        self.assertEqual(len(mod.mod.native_gadget_ids()),20)

    def test_unverified_raw_file_rejected(self):
        with self.assertRaisesRegex(ValueError,"Raw SHA mismatch"):
            mod.control(b"not original")
if __name__=="__main__":unittest.main()
