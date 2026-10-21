"""Regression of original 7.1 GadgetProp candidate's first-record falsification."""
from __future__ import annotations
from importlib import util
import json
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/audit-7.1-gadget-prop-candidate-rows.py"
_spec = util.spec_from_file_location("gadget_prop_direct_boundary_71", SCRIPT)
mod = util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


class GadgetPropCandidateBoundary71(unittest.TestCase):
    def test_first_row_original_binary_witness_is_falsification(self):
        # Prefix fields are derived from the previously SHA-pinned original source.
        # The rest of this synthetic buffer only supplies the verified payload size.
        buffer = bytearray(9388)
        struct.pack_into("<I", buffer, 0, 0x5BD30290)
        struct.pack_into("<H", buffer, 4, 0x16D8)
        struct.pack_into("<I", buffer, 6, 0x4E667B1B)
        struct.pack_into("<H", buffer, 10, 0xA31F)
        witness = mod.inspect_direct_first_record(bytes(buffer))
        self.assertEqual(witness["tableHeaderDecodedRows"], 326)
        self.assertEqual(witness["candidateDecodedMask"], "0xB9DA")
        self.assertEqual(witness["candidateStringLength"], 30606)
        self.assertEqual(witness["remainingPayloadBytes"], 9376)
        self.assertEqual(witness["candidateStringExceedsSourceByBytes"], 21230)
        self.assertFalse(witness["directAtFirstRowPossible"])

    def test_modified_source_boundary_must_fail_closed(self):
        buffer = bytearray(9388)
        struct.pack_into("<I", buffer, 0, 0x5BD30290)
        struct.pack_into("<H", buffer, 4, 0x16D8)
        struct.pack_into("<H", buffer, 10, 1)
        with self.assertRaises(ValueError):
            mod.inspect_direct_first_record(bytes(buffer))

    def test_reject_unpinned_original_raw(self):
        with self.assertRaisesRegex(ValueError, "Raw SHA-256"):
            mod.audit(b"not-original-source")


if __name__ == "__main__":
    unittest.main()
