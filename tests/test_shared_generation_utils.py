from __future__ import annotations

import unittest

import genshinre.metadata as metadata
from genshinre.samplefetch import sha256_file as samplefetch_sha256_file
from genshinre.sampleidentity import sha256_file


class SharedGenerationUtilityTests(unittest.TestCase):
    def test_sample_fetch_reuses_shared_sha256_helper(self) -> None:
        self.assertIs(sha256_file, samplefetch_sha256_file)

    def test_metadata_public_exports_have_stable_order(self) -> None:
        self.assertEqual(
            [
                "build_type_methods",
                "load_methods",
                "query_fields",
                "query_method_references",
                "query_methods",
            ],
            metadata.__all__,
        )


if __name__ == "__main__":
    unittest.main()
