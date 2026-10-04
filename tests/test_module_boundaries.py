from __future__ import annotations

import unittest
from pathlib import Path

from genshinre import mhy71
from genshinre.nativeprofile import PROFILE_71
from genshinre.registryxrefpublish import validate_known_opcodes_rows


ROOT = Path(__file__).resolve().parents[1]


class ModuleBoundaryTests(unittest.TestCase):
    def test_mhy71_target_contract_aliases_native_profile(self) -> None:
        self.assertEqual(PROFILE_71.exe_sha256, mhy71.EXPECTED_EXE_SHA256)
        self.assertEqual(PROFILE_71.metadata_sha256, mhy71.EXPECTED_METADATA_SHA256)
        self.assertEqual(PROFILE_71.type_definition_count, mhy71.EXPECTED_TYPE_COUNT)
        self.assertEqual(PROFILE_71.field_count, mhy71.EXPECTED_FIELD_COUNT)
        self.assertEqual(PROFILE_71.method_count, mhy71.EXPECTED_METHOD_COUNT)
        self.assertEqual(PROFILE_71.metadata_body_skip, mhy71.BODY_SKIP)
        self.assertEqual(PROFILE_71.embedded_header_rva, mhy71.EMBEDDED_HEADER_RVA)
        self.assertEqual(PROFILE_71.embedded_header_size, mhy71.EMBEDDED_HEADER_SIZE)
        self.assertEqual(PROFILE_71.type_array_pointer_rva, mhy71.TYPE_ARRAY_POINTER_RVA)
        self.assertEqual(PROFILE_71.method_pointer_table_rva, mhy71.METHOD_POINTER_TABLE_RVA)

    def test_known_opcode_validator_has_public_shared_entrypoint(self) -> None:
        rows = [
            {
                "cmd_id": "186",
                "semantic_name": "ExampleReq",
                "direction": "C2S",
                "status": "CONFIRMED",
                "evidence": "fixture",
            }
        ]
        self.assertEqual(rows[0], validate_known_opcodes_rows(rows)[186])

    def test_production_consumers_do_not_import_retired_private_entrypoints(self) -> None:
        cases = {
            ROOT / "tools" / "decode_protocol_handler_parameters_71.py": "_header_layout",
            ROOT / "genshinre" / "validate.py": "_validated_known_opcodes",
        }
        for path, token in cases.items():
            with self.subTest(path=path.name, token=token):
                self.assertNotIn(token, path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
