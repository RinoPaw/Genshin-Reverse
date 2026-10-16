from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.probe_graphics_aa_menu import probe, scan_metadata, scan_type_owners, verify_sample


class GraphicsAAMenuProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.sample = self.root / "sample"
        (self.sample / "metadata").mkdir(parents=True)
        self.exe = self.root / "GenshinImpact.exe"
        self.exe.write_bytes(b"synthetic test sample")
        self.sha = hashlib.sha256(self.exe.read_bytes()).hexdigest()
        (self.sample / "hashes.json").write_text(json.dumps({
            "samples": {"GenshinImpact.exe": {"sha256": self.sha}}
        }))
        self._write_csv("types.csv", "type_name,namespace,type_definition_index\n"
                        "GraphicsOptions,Unity,42\nObfuscatedThing,?,43\n")
        self._write_csv("methods.csv", "type_name,method_name,type_definition_index,method_index,rva\n"
                        "FOO,SetAntiAliasing,42,101,0x10\nBAR,SomeMethod,43,102,0x20\n")
        self._write_csv("fields.csv", "type_name,field_name,field_type,type_definition_index,field_index\n"
                        "FOO,m_antiAliasing,int,42,19\nFOO,unrelated,int,42,20\n")

    def _write_csv(self, name: str, text: str):
        (self.sample / "metadata" / name).write_text(text, encoding="utf-8")

    def test_metadata_keyword_collection(self):
        found = scan_metadata(self.sample / "metadata")
        self.assertEqual([found[n]["count"] for n in ("types.csv", "methods.csv", "fields.csv")], [1, 1, 1])
        self.assertEqual(found["methods.csv"]["rows"][0]["rva"], "0x10")

    def test_capped_metadata_still_counts_all_matches(self):
        self._write_csv("types.csv", "type_name\nGraphicsA\nGraphicsB\n")
        found = scan_metadata(self.sample / "metadata", max_rows=1)
        self.assertEqual(found["types.csv"]["count"], 2)
        self.assertEqual(len(found["types.csv"]["rows"]), 1)
        self.assertTrue(found["types.csv"]["truncated"])
        with self.assertRaises(ValueError):
            scan_metadata(self.sample / "metadata", max_rows=0)

    def test_fingerprint_fail_closed_and_unpinned_no_metadata(self):
        self.exe.write_bytes(b"different executable")
        with self.assertRaisesRegex(ValueError, "fingerprint mismatch"):
            verify_sample(self.exe, self.sample / "hashes.json")
        with patch("tools.probe_graphics_aa_menu.find_pe_string_hits", return_value=[]):
            result = probe(self.exe, sample_dir=self.sample, allow_unpinned=True)
        self.assertFalse(result["identity"]["matches_pinned_7_1_sample"])
        self.assertIsNone(result["metadata_keyword_hits"])

    def test_explicit_xrefs_only_and_metadata_sample_gate(self):
        fake_result = {"hits": [{"literal": "FSR2", "rva": "0x10"}]}
        with patch("tools.probe_graphics_aa_menu.locate_pe_string_xrefs", return_value=fake_result) as fn:
            result = probe(self.exe, sample_dir=self.sample, with_xrefs=True)
        self.assertEqual(result["pe_string_hit_count"], 1)
        self.assertEqual(result["native_xrefs"], fake_result)
        self.assertEqual(fn.call_args.kwargs["methods_csv"], self.sample / "metadata/methods.csv")

    def test_unpinned_xref_scan_never_joins_7_1_methods(self):
        self.exe.write_bytes(b"new unknown build")
        with patch("tools.probe_graphics_aa_menu.locate_pe_string_xrefs",
                   return_value={"hits": []}) as find_xrefs:
            result = probe(self.exe, sample_dir=self.sample,
                           allow_unpinned=True, with_xrefs=True)
        self.assertIsNone(find_xrefs.call_args.kwargs["methods_csv"])
        self.assertIsNone(result["metadata_keyword_hits"])

    def test_exact_type_owner_scan_includes_obfuscated_members(self):
        self._write_csv("methods.csv",
                        "type_name,method_name,type_definition_index,method_index,rva\n"
                        "ConsumerMode,ABCDEF,9384,201,0x123\n"
                        "Other,SetAntiAliasing,111,202,0x456\n")
        result = scan_type_owners(self.sample / "metadata", (9384,))
        self.assertEqual(result["methods.csv"]["count"], 1)
        self.assertEqual(result["methods.csv"]["rows"][0]["method_name"], "ABCDEF")
        self.assertEqual(result["fields.csv"]["count"], 0)

    def test_limited_literals_and_focus_indices_are_explicit(self):
        with patch("tools.probe_graphics_aa_menu.find_pe_string_hits", return_value=[]) as find:
            result = probe(self.exe, sample_dir=self.sample,
                           literals=("AntiAliasing",), focus_type_indices=(42,))
        find.assert_called_once_with(self.exe, "AntiAliasing")
        self.assertEqual(result["searched_literals"], ["AntiAliasing"])
        self.assertEqual(result["metadata_focus_type_owners"]["methods.csv"]["count"], 1)
        self.assertEqual(result["metadata_focus_type_indices"], [42])

    def test_unpinned_scan_skips_focused_type_owner_join(self):
        self.exe.write_bytes(b"other sample")
        with patch("tools.probe_graphics_aa_menu.find_pe_string_hits", return_value=[]):
            result = probe(self.exe, sample_dir=self.sample, allow_unpinned=True)
        self.assertIsNone(result["metadata_focus_type_owners"])

    def test_focus_only_skips_pe_scan_and_broad_metadata(self):
        with patch("tools.probe_graphics_aa_menu.find_pe_string_hits") as strings, \
             patch("tools.probe_graphics_aa_menu.scan_metadata") as broad:
            report = probe(self.exe, sample_dir=self.sample, focus_only=True,
                           focus_type_indices=(42,))
        strings.assert_not_called()
        broad.assert_not_called()
        self.assertEqual(report["pe_string_hits"], [])
        self.assertIsNone(report["metadata_keyword_hits"])
        self.assertEqual(report["metadata_focus_type_owners"]["methods.csv"]["count"], 1)

    def test_focus_only_rejects_native_xref_scan(self):
        with self.assertRaisesRegex(ValueError, "focus_only"):
            probe(self.exe, sample_dir=self.sample, focus_only=True, with_xrefs=True)

    def test_matching_sample_keeps_metadata(self):
        with patch("tools.probe_graphics_aa_menu.find_pe_string_hits", return_value=[]):
            result = probe(self.exe, sample_dir=self.sample)
        self.assertTrue(result["identity"]["matches_pinned_7_1_sample"])
        self.assertEqual(result["metadata_keyword_hits"]["fields.csv"]["count"], 1)


if __name__ == "__main__":
    unittest.main()
