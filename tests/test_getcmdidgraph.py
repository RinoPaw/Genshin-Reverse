from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from genshinre.getcmdidgraph import build_getcmdid_candidate_graph


class GetCmdIdCandidateGraphTests(unittest.TestCase):
    def test_filters_by_anchor_method_and_stub_shape(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "getcmdid.csv"
            output = root / "graph.csv"
            summary = root / "summary.json"
            columns = [
                "cmd_id",
                "type_name",
                "type_definition_index",
                "get_cmd_id_rva",
                "method_name",
                "pattern",
            ]
            rows = [
                [26105, "HJDNCHODGOL", 1, "0x10587260", "AEGNNPENLNM", "mov-ax-imm16-ret"],
                [9369, "DMMJNICDOHM", 2, "0xC87EA60", "AEGNNPENLNM", "mov-ax-imm16-ret"],
                [9369, "DMMJNICDOHM", 2, "0xC87EA60", "AEGNNPENLNM", "mov-ax-imm16-ret"],
                [123, "OTHER", 3, "0x111", "AEGNNPENLNM", "mov-eax-imm32-ret"],
                [456, "OTHER2", 4, "0x222", "DIFFERENT", "mov-ax-imm16-ret"],
            ]
            with source.open("w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(columns)
                writer.writerows(rows)

            result = build_getcmdid_candidate_graph(
                source,
                output,
                summary,
                anchor_cmd_id=26105,
                anchor_type_name="HJDNCHODGOL",
                anchor_rva=0x10587260,
                focus_cmd_ids=(9369, 26105),
            )

            self.assertEqual(result["row_count"], 2)
            self.assertEqual(result["unique_cmd_ids"], 2)
            self.assertEqual(result["status"], "getcmdid-static-candidate-graph")
            self.assertEqual(len(result["focus"]["9369"]), 1)
            with output.open("r", encoding="utf-8", newline="") as f:
                published = list(csv.DictReader(f))
            self.assertEqual([row["cmd_id"] for row in published], ["9369", "26105"])
            saved = json.loads(summary.read_text(encoding="utf-8"))
            self.assertIn("distinct from registry-candidate-graph", saved["notes"][1])

    def test_requires_unique_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "getcmdid.csv"
            source.write_text(
                "cmd_id,type_name,type_definition_index,get_cmd_id_rva,method_name,pattern\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "expected exactly one GetCmdId anchor"):
                build_getcmdid_candidate_graph(
                    source,
                    root / "graph.csv",
                    root / "summary.json",
                    anchor_cmd_id=26105,
                    anchor_type_name="HJDNCHODGOL",
                    anchor_rva=0x10587260,
                )


if __name__ == "__main__":
    unittest.main()
