from __future__ import annotations

import unittest
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71


class SampleSourceSingletonTests(unittest.TestCase):
    def test_maintained_scripts_and_workflows_do_not_duplicate_7_1_sample_identity(self) -> None:
        root = Path(__file__).resolve().parents[1]
        forbidden = (
            PROFILE_71.sophon_manifest_url,
            PROFILE_71.sophon_chunk_prefix,
            PROFILE_71.exe_sha256,
            PROFILE_71.metadata_sha256,
        )
        paths = [
            *sorted((root / "scripts").glob("*")),
            *sorted((root / ".github" / "workflows").glob("*.yml")),
        ]
        for path in paths:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            for value in forbidden:
                with self.subTest(path=str(path.relative_to(root)), value=value[:16]):
                    self.assertNotIn(value, text)


if __name__ == "__main__":
    unittest.main()
