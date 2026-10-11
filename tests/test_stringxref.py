from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from genshinre.stringxref import _encoded_literal, find_raw_string_hits


class StringXrefTests(unittest.TestCase):
    def test_encoding_validation(self):
        self.assertEqual(_encoded_literal("AB", "ascii"), b"AB")
        self.assertEqual(_encoded_literal("AB", "utf-16le"), bytes([65, 0, 66, 0]))
        with self.assertRaises(ValueError):
            _encoded_literal("AB", "utf-8")

    def test_raw_file_scan_distinguishes_encodings(self):
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "literal.bin"
            sample.write_bytes(bytes([0, 65, 66, 0, 65, 0, 66, 0]))
            hits = find_raw_string_hits(sample, "AB")
            self.assertEqual(
                [(hit["encoding"], hit["file_offset"]) for hit in hits],
                [("ascii", "0x1"), ("utf-16le", "0x4")],
            )
            self.assertEqual(find_raw_string_hits(sample, "NO_MATCH"), [])


if __name__ == "__main__":
    unittest.main()
