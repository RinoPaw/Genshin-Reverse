from __future__ import annotations

import unittest

from genshinre.registryusagevalidated import choose_strict_usage_layout


def candidate(
    *,
    cmd_width: int = 4,
    flag_width: int = 1,
    flag_relative: int = 8,
    protocol_rows: int = 4896,
) -> dict[str, object]:
    return {
        "cmd_column_base_rva": "0x1000",
        "cmd_width": cmd_width,
        "stride": 16,
        "anchor_22899_index_interpretation": 3118,
        "anchor_9369_cmd_rva": "0x9B80",
        "anchor_22899_cmd_rva": "0xD2E0",
        "usage_field": {"relative_to_cmd": 4, "width": 4},
        "flag_field": {"relative_to_cmd": flag_relative, "width": flag_width},
        "cmd_metrics": {
            "readable_rows": 4896,
            "nonzero_rows": 4896,
            "protocol_range_rows": protocol_rows,
            "protocol_range_ratio": protocol_rows / 4896,
            "unique_nonzero_values": 4896,
        },
        "usage_metrics": {
            "readable_rows": 4896,
            "resolved_rows": 4896,
            "resolved_ratio": 1.0,
            "unique_values": 4896,
        },
        "flag_metrics": {
            "readable_rows": 4896,
            "binary_rows": 4896,
            "binary_ratio": 1.0,
            "counts": {"0": 2400, "1": 2496, "other": 0},
        },
    }


class RegistryUsageValidatedTests(unittest.TestCase):
    def test_collapses_observationally_equivalent_width_aliases(self) -> None:
        probe = {
            "strong_candidate_count": 4,
            "candidates": [
                candidate(cmd_width=2, flag_width=1),
                candidate(cmd_width=2, flag_width=4),
                candidate(cmd_width=4, flag_width=2),
                candidate(cmd_width=4, flag_width=1),
            ],
        }
        selected = choose_strict_usage_layout(probe)
        self.assertEqual(4, selected["cmd_width"])
        self.assertEqual(1, selected["flag_field"]["width"])
        self.assertEqual([2, 4], selected["cmd_width_aliases"])
        self.assertEqual([1, 2, 4], selected["flag_width_aliases"])

    def test_rejects_distinct_flag_offsets(self) -> None:
        probe = {
            "strong_candidate_count": 2,
            "candidates": [
                candidate(flag_relative=8),
                candidate(flag_relative=9),
            ],
        }
        with self.assertRaisesRegex(ValueError, "not closed"):
            choose_strict_usage_layout(probe)

    def test_does_not_merge_widths_with_different_cmd_metrics(self) -> None:
        narrow = candidate(cmd_width=2)
        wide = candidate(cmd_width=4)
        # Keep it strong while changing a full-table observable metric.
        wide["cmd_metrics"] = dict(wide["cmd_metrics"])
        wide["cmd_metrics"]["readable_rows"] = 5000
        probe = {"strong_candidate_count": 2, "candidates": [narrow, wide]}
        with self.assertRaisesRegex(ValueError, "not closed"):
            choose_strict_usage_layout(probe)

    def test_rejects_truncated_strong_candidates(self) -> None:
        probe = {
            "strong_candidate_count": 2,
            "candidates": [candidate()],
        }
        with self.assertRaisesRegex(ValueError, "retained 1 of 2"):
            choose_strict_usage_layout(probe)


if __name__ == "__main__":
    unittest.main()
