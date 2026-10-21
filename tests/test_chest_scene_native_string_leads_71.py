"""Synthetic exact-client SceneExcel/SceneTag literal-probe scope tests."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/probe-7.1-scene-native-string-leads.py"
spec = importlib.util.spec_from_file_location("scene_native_literal_71", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class TestSceneNativeLiteralLeads71(unittest.TestCase):
    def test_missing_literal_does_not_claim_original_asset_absence(self):
        with (patch.object(probe, "require_sha256"),
              patch.object(probe, "find_pe_string_hits", return_value=[]),
              patch.object(probe, "scan_rip_xrefs") as xrefs):
            report = probe.analyze(Path("dummy.exe"), Path("methods.csv"))
        xrefs.assert_not_called()
        self.assertEqual(report["examinedLiterals"], 8)
        self.assertEqual(set(report["literalCandidates"]), set(probe.LITERALS))
        self.assertTrue(all(not x["positiveBytesOnly"]
                            for x in report["literalCandidates"].values()))
        self.assertTrue(any("does not prove absence" in x
                            for x in report["limitations"]))

    def test_positive_string_lead_retains_instruction_unverified(self):
        def hits(exe, literal, **kwargs):
            return [{
                "rva": "0x1234", "encoding": "ascii",
                "section": ".rdata",
            }] if literal == "SceneTagConfigData" else []
        with (patch.object(probe, "require_sha256"),
              patch.object(probe, "find_pe_string_hits", side_effect=hits),
              patch.object(probe, "scan_rip_xrefs", return_value={
                  "matches": {"0x1234": [{
                      "instruction_rva": "0x9876",
                      "access": "read",
                      "caller_methods": [{"method_index": "4"}],
                  }]}
              }) as xrefs):
            report = probe.analyze(Path("dummy.exe"), Path("methods.csv"))
        self.assertEqual(xrefs.call_args.args[1], [0x1234])
        found = report["literalCandidates"]["SceneTagConfigData"]
        self.assertEqual(found["exactPlainLiteralCount"], 1)
        self.assertEqual(found["hitAndCandidateReferences"][0]["rawRipReferenceCount"], 1)
        self.assertIn("SEMANTICS_UNRESOLVED", report["status"])
        self.assertNotIn("chestDropTagOwner", report)

    def test_unbounded_literal_hits_fail_closed(self):
        with (patch.object(probe, "require_sha256"),
              patch.object(probe, "find_pe_string_hits",
                           return_value=[{"rva": "0x0001"}]*51)):
            with self.assertRaisesRegex(ValueError, "unbounded native literal"):
                probe.analyze(Path("dummy.exe"), Path("methods.csv"))


if __name__ == "__main__":
    unittest.main()
