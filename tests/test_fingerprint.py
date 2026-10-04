from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from genshinre.fingerprint import fingerprint


class FingerprintDigestTests(unittest.TestCase):
    def test_fingerprint_reports_all_digests_from_same_payload(self) -> None:
        payload = b"Genshin-Reverse fingerprint fixture\n"
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "fixture.bin"
            path.write_bytes(payload)

            result = fingerprint(path)

        self.assertEqual(hashlib.sha256(payload).hexdigest(), result["sha256"])
        self.assertEqual(hashlib.sha1(payload).hexdigest(), result["sha1"])
        self.assertEqual(hashlib.md5(payload).hexdigest(), result["md5"])
        self.assertEqual(len(payload), result["size_bytes"])


if __name__ == "__main__":
    unittest.main()
