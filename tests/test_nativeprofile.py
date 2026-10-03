from __future__ import annotations

import unittest

from genshinre.nativeprofile import PROFILE_71, get_native_profile
from genshinre.typearray import (
    ANCHOR_KIND,
    ANCHOR_TYPE_DEFINITION,
    ANCHOR_TYPE_INDEX,
    ANCHOR_TYPE_NAME,
    EXPECTED_RUNTIME_TYPE_COUNT,
)


class NativeProfileTests(unittest.TestCase):
    def test_profile_identity_and_exact_sample_contract(self) -> None:
        profile = PROFILE_71

        self.assertEqual("7.1.0-global/windows-x64", profile.identity)
        self.assertEqual(
            "08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d",
            profile.exe_sha256,
        )
        self.assertEqual(
            "05ae04d7a91b91cc880217a56b0b01f3e67f845b06e894216654ec5d160e0da0",
            profile.metadata_sha256,
        )
        self.assertEqual(88_904, profile.type_definition_count)
        self.assertEqual(440_172, profile.field_count)
        self.assertEqual(733_442, profile.method_count)
        self.assertEqual(0x27D4BD0, profile.embedded_header_rva)
        self.assertEqual(0x2870AD0, profile.type_array_pointer_rva)
        self.assertEqual(0x2870B90, profile.method_pointer_table_rva)

    def test_runtime_type_contract_matches_exact_scanner(self) -> None:
        anchor = PROFILE_71.runtime_type_anchor

        self.assertEqual(EXPECTED_RUNTIME_TYPE_COUNT, PROFILE_71.runtime_type_count)
        self.assertEqual(0x388CD80, PROFILE_71.runtime_type_boundary_rva)
        self.assertEqual(ANCHOR_TYPE_INDEX, anchor.type_index)
        self.assertEqual(ANCHOR_KIND, anchor.kind)
        self.assertEqual(ANCHOR_TYPE_DEFINITION, anchor.type_definition_index)
        self.assertEqual(ANCHOR_TYPE_NAME, anchor.type_name)

    def test_getcmdid_anchor_is_part_of_profile(self) -> None:
        anchor = PROFILE_71.getcmdid_anchor

        self.assertEqual(26_105, anchor.cmd_id)
        self.assertEqual("HJDNCHODGOL", anchor.type_name)
        self.assertEqual(0x10587260, anchor.rva)

    def test_profile_lookup_is_exact(self) -> None:
        self.assertIs(PROFILE_71, get_native_profile(PROFILE_71.identity))
        with self.assertRaises(KeyError):
            get_native_profile("7.2.0-global/windows-x64")


if __name__ == "__main__":
    unittest.main()
