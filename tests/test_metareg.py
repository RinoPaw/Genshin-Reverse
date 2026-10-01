from __future__ import annotations

import unittest

from genshinre.metareg import _score_pair_run


class MetadataRegistrationTests(unittest.TestCase):
    def test_pair_run_scores_runtime_type_pointer(self) -> None:
        type_pointer = 0x142000000
        pairs = [
            {"count": 100, "pointer": {"value": "0x141000000", "mapped": True}},
            {"count": 500000, "pointer": {"value": f"0x{type_pointer:X}", "mapped": True}},
            {"count": 200, "pointer": {"value": "0x0", "mapped": False}},
        ]
        score = _score_pair_run(pairs, type_pointer)
        self.assertEqual(2, score["mapped_pointers"])
        self.assertEqual(3, score["plausible_counts"])
        self.assertTrue(score["contains_runtime_type_array"])
        self.assertEqual(15, score["score"])

    def test_pair_run_without_type_pointer_gets_no_anchor_bonus(self) -> None:
        pairs = [
            {"count": 1, "pointer": {"value": "0x141000000", "mapped": True}},
        ]
        score = _score_pair_run(pairs, 0x142000000)
        self.assertFalse(score["contains_runtime_type_array"])
        self.assertEqual(3, score["score"])


if __name__ == "__main__":
    unittest.main()
