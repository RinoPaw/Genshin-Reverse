from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from genshinre.callxref import attach_caller_methods, decode_direct_call


class DirectCallXrefTests(unittest.TestCase):
    def test_decodes_e8_rel32(self) -> None:
        instruction_rva = 0x1000
        target_rva = 0x2345
        displacement = target_rva - (instruction_rva + 5)
        code = b"\xE8" + displacement.to_bytes(4, "little", signed=True)
        row = decode_direct_call(code, 0, instruction_rva)
        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(target_rva, row["target_rva"])
        self.assertEqual(5, row["length"])

    def test_rejects_non_call_and_truncated_call(self) -> None:
        self.assertIsNone(decode_direct_call(b"\x90\x00\x00\x00\x00", 0, 0x1000))
        self.assertIsNone(decode_direct_call(b"\xE8\x00\x00", 0, 0x1000))

    def test_attaches_nearest_preceding_method_without_crossing_next_start(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "methods.csv"
            with path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=["method_index", "type_definition_index", "type_name", "method_name", "rva"],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "method_index": "1",
                        "type_definition_index": "10",
                        "type_name": "A",
                        "method_name": "First",
                        "rva": "0x1000",
                    }
                )
                writer.writerow(
                    {
                        "method_index": "2",
                        "type_definition_index": "20",
                        "type_name": "B",
                        "method_name": "Second",
                        "rva": "0x1100",
                    }
                )
                writer.writerow(
                    {
                        "method_index": "3",
                        "type_definition_index": "20",
                        "type_name": "B2",
                        "method_name": "Alias",
                        "rva": "0x1100",
                    }
                )

            result = attach_caller_methods([0x1050, 0x1120, 0x5000], path, max_method_body=0x200)
            self.assertEqual(["First"], [row["method_name"] for row in result[0x1050]])
            self.assertEqual({"Second", "Alias"}, {row["method_name"] for row in result[0x1120]})
            self.assertEqual([], result[0x5000])


if __name__ == "__main__":
    unittest.main()
