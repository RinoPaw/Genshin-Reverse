"""Original 7.1 Scene Point-compatible 31 native element factory class slot audit."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts/probe-7.1-point-factory-class-slot-xrefs.py"
spec=importlib.util.spec_from_file_location("factory_slot71",SCRIPT)
p=importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
REPORT=ROOT/p.ORIGINAL_FACTORY_REPORT


class OriginalFactorySlotReferences(unittest.TestCase):
    def test_original_factory_source_and_exact_numeric_slot_pair(self):
        cases=p.source_factory_slots(REPORT)
        self.assertEqual(len(cases),31)
        self.assertEqual(cases[1]["nativeRuntimeClassSlotRva"],"0x57C37B0")
        self.assertEqual(cases[14]["nativeRuntimeClassSlotRva"],"0x57C1970")
        self.assertEqual(cases[1]["nativeBranchRva"],"0xC591C94")
        self.assertEqual(cases[14]["nativeBranchRva"],"0xC591DF4")
        self.assertEqual(p.TARGET_CASES,(1,14))
        self.assertEqual(len(p.PREFIXES),64)

    def test_pinned_method_index(self):
        with tempfile.TemporaryDirectory() as d:
            file=Path(d)/"methods.csv"
            file.write_bytes(b"untrusted")
            with patch.object(p,"git_blob",return_value="wrong"):
                with self.assertRaisesRegex(ValueError,"Git blob changed"):
                    p.scan(Path("nonexistent"),file,REPORT)

    def test_untrusted_factory_report_fails(self):
        with tempfile.TemporaryDirectory() as d:
            file=Path(d)/"report.json"
            file.write_text('{"originalExeSha256":"WRONG"}',encoding="utf-8")
            with self.assertRaises(KeyError):
                p.source_factory_slots(file)


if __name__=="__main__":
    unittest.main()
