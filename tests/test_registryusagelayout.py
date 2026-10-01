from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from genshinre.registrylayout import ANCHOR_22899, ANCHOR_9369, _flag_field_matches
from genshinre.registryusagelayout import (
    _flag_column_metrics,
    _usage_column_metrics,
    _usage_field_matches,
    resolve_anchor_usage_destinations,
)


class FakeImage:
    def __init__(self, data: bytes):
        self.data = data

    def read_rva(self, rva: int, size: int) -> bytes:
        if rva < 0 or rva >= len(self.data):
            return b""
        return self.data[rva : rva + size]


class RegistryUsageLayoutTests(unittest.TestCase):
    def test_resolve_anchor_usage_destinations_by_type_and_slot(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "usage-types.csv"
            with path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=("usage_destination", "type_slot_rva", "type_name"),
                )
                writer.writeheader()
                writer.writerows(
                    [
                        {"usage_destination": "37523", "type_slot_rva": "0x57E6498", "type_name": "DMMJNICDOHM"},
                        {"usage_destination": "42000", "type_slot_rva": "0x57F6F60", "type_name": "ONKOPMILDMF"},
                    ]
                )
            self.assertEqual({9369: 37523, 22899: 42000}, resolve_anchor_usage_destinations(path))

    def test_usage_and_flag_columns_share_relative_offsets(self) -> None:
        stride = 12
        rows = 10
        data = bytearray(stride * rows)
        usages = set()
        for index in range(rows):
            usage = 100 + index
            usages.add(usage)
            base = index * stride
            data[base + 2] = index & 1
            data[base + 4 : base + 8] = usage.to_bytes(4, "little")

        index1 = 2
        index2 = 7
        base1 = index1 * stride
        base2 = index2 * stride
        data[base1 + 2] = 1
        data[base2 + 2] = 0
        image = FakeImage(bytes(data))

        usage_matches = _usage_field_matches(
            image,
            base1,
            base2,
            stride,
            100 + index1,
            100 + index2,
        )
        self.assertIn({"relative_to_cmd": 4, "width": 4}, usage_matches)

        flag_matches = _flag_field_matches(
            image,
            base1,
            base2,
            stride,
            ANCHOR_9369,
            ANCHOR_22899,
        )
        self.assertTrue(any(item["relative_to_cmd"] == 2 for item in flag_matches))

        usage_metrics = _usage_column_metrics(image, 4, stride, rows, usages)
        self.assertEqual(1.0, usage_metrics["resolved_ratio"])
        flag_metrics = _flag_column_metrics(image, 2, stride, 1, rows)
        self.assertEqual(1.0, flag_metrics["binary_ratio"])


if __name__ == "__main__":
    unittest.main()
