from __future__ import annotations

import json
import unittest
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71


ROOT = Path(__file__).resolve().parents[1]
VERSION = ROOT / "versions/7.1.0-global/windows-x64"


class CommittedNativeProfileTests(unittest.TestCase):
    def test_profile_matches_version_identity_and_samples(self) -> None:
        hashes = json.loads((VERSION / "hashes.json").read_text(encoding="utf-8"))
        profile = PROFILE_71

        self.assertEqual(profile.version, hashes["game_version"])
        self.assertEqual(profile.region, hashes["region"])
        self.assertEqual(profile.platform, hashes["platform"])
        self.assertEqual(
            profile.exe_sha256,
            hashes["samples"]["GenshinImpact.exe"]["sha256"],
        )
        self.assertEqual(
            profile.metadata_sha256,
            hashes["samples"]["global-metadata.dat"]["sha256"],
        )

    def test_profile_matches_publication_contract(self) -> None:
        manifest = json.loads(
            (VERSION / "generated-artifacts.json").read_text(encoding="utf-8")
        )
        validation = manifest["validation"]
        counts = validation["metadata_counts"]
        profile = PROFILE_71

        self.assertEqual(profile.type_definition_count, counts["types"])
        self.assertEqual(profile.field_count, counts["fields"])
        self.assertEqual(profile.method_count, counts["methods"])
        self.assertEqual(profile.method_count, counts["method_pointers"])
        self.assertEqual(profile.exe_sha256, validation["sample"]["exe_sha256"])
        self.assertEqual(profile.metadata_sha256, validation["sample"]["metadata_sha256"])
        self.assertEqual(profile.runtime_type_count, validation["runtime_type_count"])
        self.assertEqual(
            profile.runtime_type_boundary_rva,
            int(validation["runtime_type_boundary_rva"], 0),
        )
        self.assertTrue(validation["runtime_type_boundary_verified"])
        self.assertTrue(validation["runtime_type_anchor"])
        self.assertTrue(validation["getcmdid_anchor"])

    def test_profile_matches_runtime_type_summary(self) -> None:
        summary = json.loads(
            (VERSION / "metadata/runtime-types.summary.json").read_text(encoding="utf-8")
        )
        profile = PROFILE_71
        anchor = profile.runtime_type_anchor
        anchor_kind = "class" if anchor.kind == 0x12 else f"kind_0x{anchor.kind:02X}"
        anchor_key = (
            f"anchor_{anchor.type_index}_{anchor_kind}_"
            f"{anchor.type_definition_index}_{anchor.type_name}"
        )

        self.assertEqual(profile.exe_sha256, summary["exe_sha256"])
        self.assertEqual(
            profile.type_array_pointer_rva,
            int(summary["type_array_pointer_source_rva"], 0),
        )
        self.assertEqual(profile.runtime_type_count, summary["runtime_type_count"])
        self.assertEqual(profile.runtime_type_boundary_rva, int(summary["boundary_rva"], 0))
        self.assertFalse(summary["boundary_entry_valid_type"])
        self.assertTrue(summary["structural_validation_passed"])
        self.assertTrue(summary[anchor_key])


if __name__ == "__main__":
    unittest.main()
