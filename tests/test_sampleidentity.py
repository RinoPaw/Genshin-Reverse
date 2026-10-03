from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from genshinre.sampleidentity import require_sha256, sha256_file


class SampleIdentityTests(unittest.TestCase):
    def test_sha256_file_and_required_digest_match(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "sample.bin"
            path.write_bytes(b"genshin-reverse")
            expected = hashlib.sha256(b"genshin-reverse").hexdigest()

            self.assertEqual(expected, sha256_file(path, chunk_size=3))
            self.assertEqual(expected, require_sha256(path, expected))

    def test_required_digest_rejects_sample_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "sample.bin"
            path.write_bytes(b"wrong")
            expected = hashlib.sha256(b"right").hexdigest()

            with self.assertRaisesRegex(ValueError, "unexpected test sample SHA-256"):
                require_sha256(path, expected, label="test sample")

    def test_required_digest_rejects_invalid_expected_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "sample.bin"
            path.write_bytes(b"x")

            with self.assertRaisesRegex(ValueError, "64-character hexadecimal"):
                require_sha256(path, "abc")
            with self.assertRaisesRegex(ValueError, "must be hexadecimal"):
                require_sha256(path, "z" * 64)

    def test_sha256_rejects_nonpositive_chunk_size(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "sample.bin"
            path.write_bytes(b"x")

            with self.assertRaisesRegex(ValueError, "chunk_size must be positive"):
                sha256_file(path, chunk_size=0)


if __name__ == "__main__":
    unittest.main()
