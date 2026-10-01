from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from genshinre.registryusageraw import _usage_identity_index, choose_closed_usage_layout


def strong_candidate(*, cmd_width: int, flag_width: int, flag_relative: int = 2) -> dict[str, object]:
    return {
        "cmd_column_base_rva": "0x1000",
        "cmd_width": cmd_width,
        "stride": 12,
        "anchor_22899_index_interpretation": 3117,
        "usage_field": {"relative_to_cmd": 4, "width": 4},
        "flag_field": {"relative_to_cmd": flag_relative, "width": flag_width},
        "cmd_metrics": {
            "unique_nonzero_values": 4896,
            "protocol_range_ratio": 1.0,
        },
        "usage_metrics": {"resolved_ratio": 1.0},
        "flag_metrics": {"binary_ratio": 1.0},
    }


class RegistryUsageRawTests(unittest.TestCase):
    def test_closes_width_only_aliases(self) -> None:
        probe = {
            "strong_candidate_count": 4,
            "candidates": [
                strong_candidate(cmd_width=2, flag_width=1),
                strong_candidate(cmd_width=2, flag_width=4),
                strong_candidate(cmd_width=4, flag_width=2),
                strong_candidate(cmd_width=4, flag_width=1),
            ],
        }
        selected = choose_closed_usage_layout(probe)
        self.assertEqual(4, selected["cmd_width"])
        self.assertEqual(1, selected["flag_field"]["width"])
        self.assertEqual(2, selected["flag_field"]["relative_to_cmd"])

    def test_rejects_distinct_flag_offsets(self) -> None:
        probe = {
            "strong_candidate_count": 2,
            "candidates": [
                strong_candidate(cmd_width=4, flag_width=1, flag_relative=2),
                strong_candidate(cmd_width=4, flag_width=1, flag_relative=3),
            ],
        }
        with self.assertRaisesRegex(ValueError, "not closed"):
            choose_closed_usage_layout(probe)

    def test_rejects_truncated_strong_candidates(self) -> None:
        probe = {
            "strong_candidate_count": 2,
            "candidates": [strong_candidate(cmd_width=4, flag_width=1)],
        }
        with self.assertRaisesRegex(ValueError, "retained 1 of 2"):
            choose_closed_usage_layout(probe)

    def test_usage_identity_index_preserves_multiple_slots(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "usage-types.csv"
            with path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=(
                        "usage_destination",
                        "type_slot_rva",
                        "type_index",
                        "type_definition_index",
                        "type_name",
                    ),
                )
                writer.writeheader()
                writer.writerows(
                    [
                        {
                            "usage_destination": "100",
                            "type_slot_rva": "0x2000",
                            "type_index": "12",
                            "type_definition_index": "34",
                            "type_name": "ABC",
                        },
                        {
                            "usage_destination": "100",
                            "type_slot_rva": "0x3000",
                            "type_index": "12",
                            "type_definition_index": "34",
                            "type_name": "ABC",
                        },
                    ]
                )
            index = _usage_identity_index(path)
            self.assertTrue(index[100]["resolved"])
            self.assertFalse(index[100]["ambiguous"])
            self.assertEqual((0x2000, 0x3000), index[100]["type_slot_rvas"])
            self.assertEqual("ABC", index[100]["type_name"])


if __name__ == "__main__":
    unittest.main()
