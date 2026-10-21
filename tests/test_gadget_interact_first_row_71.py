"""Original 7.1 native GadgetInteract first mask branch behavior."""
from importlib import util
from pathlib import Path
import struct
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=util.spec_from_file_location("original_gadget_interact",ROOT/"scripts/probe-7.1-gadget-interact-first-row.py")
m=util.module_from_spec(spec)
spec.loader.exec_module(m)


class TestInteractNativeBranch(unittest.TestCase):
    def make_payload(self,byte:int)->bytes:
        return struct.pack("<I",0x25D9D16D)+bytes([byte])+bytes(24)

    def test_branch_to_nested_reader_is_preserved(self):
        record=m.inspect_prefix(self.make_payload(1))
        self.assertTrue(record["rawBitZeroRequiresNestedReaderCall"])
        self.assertEqual(record["candidateDecodedMaskByte"],"0x75")
        self.assertEqual(record["nativeNestedReaderDirectCallRva"],"0xFF7AE70")
        self.assertFalse(record["recordBoundaryConfirmed"])

    def test_branch_without_nested_reader(self):
        record=m.inspect_prefix(self.make_payload(0x74))
        self.assertFalse(record["rawBitZeroRequiresNestedReaderCall"])
        self.assertEqual(record["candidateDecodedMaskByte"],"0x00")
        self.assertFalse(record["candidateHasConditionalStringRead"])
        self.assertFalse(record["candidateHasConditionalU32KeyRead"])
        self.assertIsNone(record["preWrapperKeyIfUninterrupted"])

    def test_native_candidate_uninterrupted_first_key(self):
        original_word=0x12345678
        payload=struct.pack("<I",0x25D9D16D)+bytes([0x36])+struct.pack("<I",original_word)+bytes(12)
        record=m.inspect_prefix(payload)
        self.assertEqual(record["candidateDecodedMaskByte"],"0x42")
        self.assertEqual(record["preWrapperKeyIfUninterrupted"],
                         ((original_word ^ 0x2B845856)+0x8B76314E)&0xffffffff)
        self.assertEqual(record["nativePrefixCursorIfUninterrupted"],9)
        self.assertFalse(record["recordBoundaryConfirmed"])

    def test_wrong_original_count_rejected(self):
        with self.assertRaisesRegex(ValueError,"row count mismatch"):
            m.inspect_prefix(struct.pack("<I",0)+bytes([0])*20)

    def test_sha_gate_rejects_other_asset(self):
        with self.assertRaisesRegex(ValueError,"Raw SHA-256"):
            m.probe(b"unverified")


if __name__=="__main__":unittest.main()
