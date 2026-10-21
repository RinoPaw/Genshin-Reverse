"""Verify GadgetProp row byte order and native reader candidate transforms."""
from __future__ import annotations
from importlib import util
from pathlib import Path
import struct
import unittest
from genshinre.binconfig import BinaryConfigReader

ROOT = Path(__file__).resolve().parents[1]
SPEC = util.spec_from_file_location("native_gadget_prop_candidate",ROOT/"scripts/audit-7.1-gadget-prop-candidate-rows.py")
mod = util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class OriginalGadgetPropCandidateTests(unittest.TestCase):
    def test_exact_mask_and_integer_field_sequence(self):
        encoded_mask=(0x8D-mod.MASK_ADD)&0xFFFF
        payload=struct.pack("<HIIII",encoded_mask,
            0xFE010203,4,2,3)
        reader=BinaryConfigReader(payload)
        self.assertEqual(mod.decode_mask(encoded_mask),0x8D)
        row=mod.candidate_row(reader,0)
        self.assertEqual(row["nativeMask"],"0x008D")
        self.assertEqual(row["fields"]["0x20"],0xFE010203^0x89E1EE3D)
        self.assertEqual(row["fields"]["0x1C"],(4+0xFA34DCA4)&0xffffffff)
        self.assertEqual(row["fields"]["0x18"],(2+0xFFE30423)&0xffffffff)
        self.assertEqual(row["fields"]["0x24"],(3+0x4649B56A)&0xffffffff)
        self.assertEqual(reader.pos,18)

    def test_wrong_original_mask_is_rejected(self):
        with self.assertRaisesRegex(ValueError,"unsupported"):
            mod.decode_mask((0x10-mod.MASK_ADD)&0xFFFF)

    def test_wrong_original_raw_sha_is_rejected(self):
        with self.assertRaisesRegex(ValueError,"raw SHA-256 mismatch"):
            mod.scan(b"fictional client bytes")


if __name__=="__main__":
    unittest.main()
