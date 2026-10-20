"""Offline contracts for the pinned Sophon chest design-block fetcher."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/fetch-7.1-design-blocks.py"
spec = importlib.util.spec_from_file_location("fetch_chest_design_blocks_71", SCRIPT)
fetcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetcher)


def fingerprints(data: bytes):
    return (len(data), hashlib.md5(data).hexdigest(),
            hashlib.sha256(data).hexdigest())


class TestChestDesignBlockFetcher(unittest.TestCase):
    def test_official_manifest_paths_and_both_hashes(self):
        blobs = {31049741: b"synthetic official index", 25539185: b"synthetic excel"}
        fake_blocks = {key: fingerprints(blob) for key, blob in blobs.items()}
        rows = [{"filename": fetcher.PREFIX + f"{key}.blk"} for key in blobs]
        def reconstruct(prefix, row, path, workers):
            key = int(Path(row["filename"]).stem)
            path.write_bytes(blobs[key])
        with TemporaryDirectory() as directory, \
                patch.object(fetcher, "BLOCKS", fake_blocks), \
                patch.object(fetcher, "download", return_value=b"manifest"), \
                patch.object(fetcher, "decompress_zstd", return_value=b"decoded"), \
                patch.object(fetcher, "parse_manifest", return_value=rows), \
                patch.object(fetcher, "reconstruct", side_effect=reconstruct):
            output = Path(directory)
            result = fetcher.fetch_blocks(output)
            self.assertEqual(len(result["blocks"]), 2)
            self.assertEqual((output / "31049741.blk").read_bytes(), blobs[31049741])
            self.assertEqual(result["blocks"][0]["sha256"], fake_blocks[31049741][2])
            self.assertEqual(result["sample"], "7.1.0-global/windows-x64")
            # Existing copies must still be verified. Never silently trust cache.
            (output / "31049741.blk").write_bytes(b"wrong bytes")
            with self.assertRaisesRegex(ValueError, "mismatch"):
                fetcher.fetch_blocks(output)

    def test_wrong_bytes_rejected_before_publication(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "31049741.blk"
            path.write_bytes(b"bad")
            with self.assertRaisesRegex(ValueError, "mismatch"):
                fetcher.verify(path, 31049741)
        with self.assertRaisesRegex(ValueError, "positive"):
            fetcher.fetch_blocks(Path("unused"), workers=0)

    def test_misleading_manifest_basename_rejected(self):
        data = b"short"
        with TemporaryDirectory() as directory, \
                patch.object(fetcher, "BLOCKS", {31049741: fingerprints(data)}), \
                patch.object(fetcher, "download", return_value=b"manifest"), \
                patch.object(fetcher, "decompress_zstd", return_value=b"decoded"), \
                patch.object(fetcher, "parse_manifest", return_value=[
                    {"filename": "some/other/31049741.blk"}
                ]):
            with self.assertRaisesRegex(ValueError, "unexpected manifest path"):
                fetcher.fetch_blocks(Path(directory))


if __name__ == "__main__":
    unittest.main()
