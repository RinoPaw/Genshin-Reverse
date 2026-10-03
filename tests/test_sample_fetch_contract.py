from __future__ import annotations

import json
import unittest
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71
from genshinre.samplefetch import _resolve_source, build_parser


class SampleFetchContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[1]
        self.sh = (self.root / "scripts/fetch-7.1-samples.sh").read_text(encoding="utf-8")
        self.ps1 = (self.root / "scripts/fetch-7.1-samples.ps1").read_text(encoding="utf-8")
        self.hashes = json.loads(
            (self.root / "versions/7.1.0-global/windows-x64/hashes.json").read_text(encoding="utf-8")
        )

    def test_profile_owns_pinned_sophon_source(self) -> None:
        profile = PROFILE_71
        self.assertIn("/sophon/manifests/", profile.sophon_manifest_url)
        self.assertIn("/sMXGW2ll3Fuu/", profile.sophon_manifest_url)
        self.assertTrue(profile.sophon_chunk_prefix.endswith("/sMXGW2ll3Fuu"))

    def test_shell_wrappers_only_reference_profile_identity(self) -> None:
        profile = PROFILE_71
        for text in (self.sh, self.ps1):
            self.assertIn("genshinre.samplefetch", text)
            self.assertIn(profile.identity, text)
            self.assertNotIn(profile.sophon_manifest_url, text)
            self.assertNotIn(profile.sophon_chunk_prefix, text)
            self.assertNotIn(profile.exe_sha256, text)
            self.assertNotIn(profile.metadata_sha256, text)

    def test_profile_hashes_match_version_provenance(self) -> None:
        self.assertEqual(
            PROFILE_71.exe_sha256,
            self.hashes["samples"]["GenshinImpact.exe"]["sha256"],
        )
        self.assertEqual(
            PROFILE_71.metadata_sha256,
            self.hashes["samples"]["global-metadata.dat"]["sha256"],
        )
        self.assertEqual(self.hashes["game_version"], PROFILE_71.version)
        self.assertEqual(self.hashes["region"], PROFILE_71.region)
        self.assertEqual(self.hashes["platform"], PROFILE_71.platform)

    def test_profile_mode_resolves_source_without_explicit_duplicates(self) -> None:
        args = build_parser().parse_args(
            ["--profile", PROFILE_71.identity, "--output", "out"]
        )
        manifest, chunks, exe_sha, metadata_sha, manifest_md5 = _resolve_source(args)
        self.assertEqual(PROFILE_71.sophon_manifest_url, manifest)
        self.assertEqual(PROFILE_71.sophon_chunk_prefix, chunks)
        self.assertEqual(PROFILE_71.exe_sha256, exe_sha)
        self.assertEqual(PROFILE_71.metadata_sha256, metadata_sha)
        self.assertEqual(PROFILE_71.sophon_manifest_md5, manifest_md5)

    def test_generic_explicit_mode_remains_available_for_research_samples(self) -> None:
        args = build_parser().parse_args(
            [
                "--manifest-url",
                "https://example.invalid/manifest",
                "--chunk-prefix",
                "https://example.invalid/chunks",
                "--expected-exe-sha256",
                "a" * 64,
                "--expected-metadata-sha256",
                "b" * 64,
                "--output",
                "out",
            ]
        )
        source = _resolve_source(args)
        self.assertEqual("https://example.invalid/manifest", source[0])
        self.assertEqual("https://example.invalid/chunks", source[1])
        self.assertEqual("a" * 64, source[2])
        self.assertEqual("b" * 64, source[3])


if __name__ == "__main__":
    unittest.main()
