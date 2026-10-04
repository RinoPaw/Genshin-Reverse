from __future__ import annotations

import unittest

from genshinre.contracts import ANALYSIS_STATUSES
from genshinre.nativeprofile import PROFILE_71
from genshinre.registry import ALLOWED_STATUS, EXPECTED_REGISTRY_ROW_COUNT
from genshinre.rowutil import int_matches, parse_optional_int


class RowUtilTests(unittest.TestCase):
    def test_parse_optional_int_accepts_decimal_and_prefixed_hex(self) -> None:
        self.assertEqual(186, parse_optional_int("186"))
        self.assertEqual(186, parse_optional_int("0xBA"))
        self.assertEqual(-1, parse_optional_int("-1"))

    def test_parse_optional_int_rejects_blank_and_invalid_values(self) -> None:
        self.assertIsNone(parse_optional_int(""))
        self.assertIsNone(parse_optional_int("   "))
        self.assertIsNone(parse_optional_int(None))
        self.assertIsNone(parse_optional_int("not-an-int"))

    def test_int_matches_preserves_optional_filter_semantics(self) -> None:
        self.assertTrue(int_matches("not-an-int", None))
        self.assertTrue(int_matches("0xBA", 186))
        self.assertFalse(int_matches("185", 186))
        self.assertFalse(int_matches("not-an-int", 186))

    def test_registry_contract_uses_shared_profile_and_analysis_states(self) -> None:
        self.assertEqual(PROFILE_71.registry_row_count, EXPECTED_REGISTRY_ROW_COUNT)
        self.assertTrue(ANALYSIS_STATUSES.issubset(ALLOWED_STATUS))


if __name__ == "__main__":
    unittest.main()
