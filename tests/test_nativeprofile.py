from __future__ import annotations

import unittest

from genshinre import mhy71, registryslots, registryslotxref, registryxrefpublish
from genshinre.nativeprofile import PROFILE_71, get_native_profile


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

    def test_runtime_type_contract_is_explicit(self) -> None:
        anchor = PROFILE_71.runtime_type_anchor

        self.assertEqual(683_574, PROFILE_71.runtime_type_count)
        self.assertEqual(0x388CD80, PROFILE_71.runtime_type_boundary_rva)
        self.assertEqual(405_772, anchor.type_index)
        self.assertEqual(0x12, anchor.kind)
        self.assertEqual(84_249, anchor.type_definition_index)
        self.assertEqual("DMMJNICDOHM", anchor.type_name)

    def test_getcmdid_anchor_is_part_of_profile(self) -> None:
        anchor = PROFILE_71.getcmdid_anchor

        self.assertEqual(26_105, anchor.cmd_id)
        self.assertEqual("HJDNCHODGOL", anchor.type_name)
        self.assertEqual(0x10587260, anchor.rva)

    def test_registry_slot_contract_is_part_of_profile(self) -> None:
        profile = PROFILE_71

        self.assertEqual(4_896, profile.registry_row_count)
        self.assertEqual(0x07F7D800, profile.registry_code_min_rva)
        self.assertEqual(0x07F8E500, profile.registry_code_max_rva)
        self.assertEqual((2_232, 3_118), tuple(anchor.index for anchor in profile.registry_slot_anchors))

        unlock, born = profile.registry_slot_anchors
        self.assertEqual(
            (9_369, "DMMJNICDOHM", 84_249, 2_232, 0x057E6498, 0x07F852AB),
            (
                unlock.cmd_id,
                unlock.type_name,
                unlock.type_definition_index,
                unlock.index,
                unlock.type_slot_rva,
                unlock.store_rva,
            ),
        )
        self.assertEqual(
            (22_899, "ONKOPMILDMF", 87_483, 3_118, 0x057F6F60, None),
            (
                born.cmd_id,
                born.type_name,
                born.type_definition_index,
                born.index,
                born.type_slot_rva,
                born.store_rva,
            ),
        )

    def test_metadata_decoder_contract_matches_profile(self) -> None:
        profile = PROFILE_71

        self.assertEqual(profile.exe_sha256, mhy71.EXPECTED_EXE_SHA256)
        self.assertEqual(profile.metadata_sha256, mhy71.EXPECTED_METADATA_SHA256)
        self.assertEqual(profile.type_definition_count, mhy71.EXPECTED_TYPE_COUNT)
        self.assertEqual(profile.field_count, mhy71.EXPECTED_FIELD_COUNT)
        self.assertEqual(profile.method_count, mhy71.EXPECTED_METHOD_COUNT)
        self.assertEqual(profile.metadata_body_skip, mhy71.BODY_SKIP)
        self.assertEqual(profile.embedded_header_rva, mhy71.EMBEDDED_HEADER_RVA)
        self.assertEqual(profile.embedded_header_size, mhy71.EMBEDDED_HEADER_SIZE)
        self.assertEqual(profile.type_array_pointer_rva, mhy71.TYPE_ARRAY_POINTER_RVA)
        self.assertEqual(profile.method_pointer_table_rva, mhy71.METHOD_POINTER_TABLE_RVA)

    def test_registry_slot_decoder_contract_matches_profile(self) -> None:
        profile = PROFILE_71

        self.assertEqual(profile.registry_row_count, registryslots.EXPECTED_REGISTRY_ROWS)
        self.assertEqual(profile.registry_code_min_rva, registryslots.REGISTRY_CODE_MIN_RVA)
        self.assertEqual(profile.registry_code_max_rva, registryslots.REGISTRY_CODE_MAX_RVA)
        for anchor in profile.registry_slot_anchors:
            observed = registryslots.ANCHORS[anchor.index]
            self.assertEqual(anchor.type_slot_rva, observed["type_slot_rva"])
            self.assertEqual(anchor.store_rva, observed["store_rva"])
            self.assertEqual(anchor.name, observed["name"])

    def test_registry_relationship_contract_matches_profile(self) -> None:
        profile = PROFILE_71
        by_index = {anchor.index: anchor for anchor in profile.registry_slot_anchors}

        self.assertEqual(profile.registry_row_count, registryslotxref.EXPECTED_REGISTRY_ROWS)
        self.assertEqual(profile.registry_row_count, registryxrefpublish.EXPECTED_ROWS)

        for cmd_id, observed in registryslotxref.ANCHORS.items():
            anchor = by_index[observed["registry_index"]]
            self.assertEqual(anchor.cmd_id, cmd_id)
            self.assertEqual(anchor.type_name, observed["type_name"])
            self.assertEqual(anchor.type_slot_rva, observed["registry_slot_rva"])

        for cmd_id, observed in registryxrefpublish.ANCHORS.items():
            anchor = by_index[observed["index"]]
            self.assertEqual(anchor.cmd_id, cmd_id)
            self.assertEqual(anchor.type_name, observed["type_name"])
            self.assertEqual(anchor.type_definition_index, observed["tdi"])
            self.assertEqual(anchor.type_slot_rva, observed["slot"])

    def test_profile_lookup_is_exact(self) -> None:
        self.assertIs(PROFILE_71, get_native_profile(PROFILE_71.identity))
        with self.assertRaises(KeyError):
            get_native_profile("7.2.0-global/windows-x64")


if __name__ == "__main__":
    unittest.main()
