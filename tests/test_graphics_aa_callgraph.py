from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.research_graphics_aa_callgraph import (
    analyze, extract_direct_edges, load_method_owners, nearest_owner,
)


class GraphicsAAUIEdgesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.sample = self.root / "sample"
        (self.sample / "metadata").mkdir(parents=True)
        self.exe = self.root / "GenshinImpact.exe"
        self.exe.write_bytes(b"fake executable")
        sha = hashlib.sha256(self.exe.read_bytes()).hexdigest()
        (self.sample / "hashes.json").write_text(json.dumps({
            "samples": {"GenshinImpact.exe": {"sha256": sha}}
        }))
        (self.sample / "metadata/methods.csv").write_text(
            "method_index,type_definition_index,type_name,method_name,rva,parameter_types\n"
            "1,18970,MonoSettingGraphicsTab,Setup,0x1000,[]\n"
            "2,18970,MonoSettingGraphicsTab,Alias,0x1000,[]\n"
            "3,13019,MonoSettingGroup,OnChoose,0x1100,[]\n"
            "4,100,Other,OtherMethod,0x1200,[]\n"
            "5,18970,MonoSettingGraphicsTab,Missing,\n",
            encoding="utf-8",
        )

    def test_target_owner_selection_keeps_rva_aliases(self):
        starts, by_rva, focus = load_method_owners(
            self.sample / "metadata/methods.csv", (18970, 13019))
        self.assertEqual(starts, [0x1000, 0x1100, 0x1200])
        self.assertEqual(len(focus[0x1000]), 2)
        self.assertEqual(len(focus[0x1100]), 1)
        self.assertEqual(len(by_rva[0x1200]), 1)
        self.assertNotIn(0x1200, focus)

    def test_bounded_owner_is_candidate_not_unlimited_range(self):
        starts, by_rva, focus = load_method_owners(
            self.sample / "metadata/methods.csv", (18970,))
        self.assertIsNone(nearest_owner(0x0, starts, by_rva))
        self.assertEqual(nearest_owner(0x1010, starts, by_rva)["start_rva"], "0x1000")
        self.assertEqual(nearest_owner(0x1210, starts, by_rva,
                                      max_owner_size=0x10), None)

    def test_sample_mismatch_fails_before_native_scanning(self):
        self.exe.write_bytes(b"unrelated client")
        with patch("tools.research_graphics_aa_callgraph.PEImage") as native:
            with self.assertRaisesRegex(ValueError, "fingerprint mismatch"):
                analyze(self.exe, sample_dir=self.sample)
        native.assert_not_called()

    def test_native_analysis_uses_narrow_method_intervals(self):
        class FakePE:
            image_base = 0x140000000
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read_rva(self, rva, count):
                return b"\x90" * count
        with patch("tools.research_graphics_aa_callgraph.PEImage", return_value=FakePE()), \
             patch("tools.research_graphics_aa_callgraph.extract_direct_edges",
                   return_value={"direct_branch_count": 0, "truncated": False,
                                 "decoded_bytes": 0, "edges": []}) as edges:
            report = analyze(self.exe, sample_dir=self.sample,
                             owners=(18970, 13019), max_body=0x80)
        self.assertEqual(report["method_count"], 3)
        self.assertEqual(report["unique_method_rvas"], 2)
        self.assertEqual(report["methods"][0]["read_size"], 0x80)
        self.assertTrue(report["methods"][0]["body_truncated"])
        self.assertEqual(edges.call_count, 2)

    def test_invalid_max_edges_rejected_before_optional_disassembler_import(self):
        with self.assertRaisesRegex(ValueError, "max_edges"):
            extract_direct_edges(
                b"\\x90", image_base=0x140000000, start_rva=0x1000,
                starts=[], by_rva={}, max_edges=0,
            )

    def test_no_owners_and_too_small_body_rejected(self):
        with self.assertRaisesRegex(ValueError, "at least one owner"):
            analyze(self.exe, sample_dir=self.sample, owners=())
        with self.assertRaisesRegex(ValueError, "max_body"):
            analyze(self.exe, sample_dir=self.sample, max_body=8)


if __name__ == "__main__":
    unittest.main()
