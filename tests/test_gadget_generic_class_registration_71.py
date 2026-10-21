"""Original 7.1 generic class registration type layout reading smoke tests."""
from __future__ import annotations
from importlib import util
from pathlib import Path
import struct
import unittest

ROOT=Path(__file__).resolve().parents[1]
_spec=util.spec_from_file_location("original_generic_classes",ROOT/"scripts/probe-7.1-gadget-generic-class-registration.py")
mod=util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


class OriginalGenericRegistration(unittest.TestCase):
    def test_published_original_registration_negative_scope(self):
        import json
        report=json.loads((ROOT/"versions/7.1.0-global/analyses/progression/economy/7.1-gadget-aux-generic-registration-boundary.json").read_text(encoding="utf-8"))
        self.assertEqual(report["exeSha256"],mod.PROFILE_71.exe_sha256)
        self.assertEqual(report["metadataRegistrationPairSignatureCandidateCount"],0)
        self.assertEqual(report["countMarkerDiagnostics"]["typeDefinitions"]["alignedQwordOccurrenceCount"],1)
        self.assertEqual(report["countMarkerDiagnostics"]["runtimeTypes"]["alignedQwordOccurrenceCount"],0)
        self.assertEqual(report["metadataRegistrationCandidates"],[])

    def test_original_four_managers_hypothetical_indices(self):
        self.assertEqual(mod.GENERIC_INDICES["GadgetPropManagerGenericField"],0x2B581)
        self.assertEqual(mod.GENERIC_INDICES["GadgetInteractManagerGenericField"],0x2A6A4)
        self.assertEqual(mod.GENERIC_INDICES["SceneTagManagerGenericFieldControl"],0x35C81)
        self.assertEqual(mod.GENERIC_INDICES["SceneExcelManagerGenericFieldControl"],0x28AC3)

    def test_seven_pairs_layout(self):
        data=b"".join(struct.pack("<QQ",i+7,0x140000000+i*128) for i in range(7))
        result=mod.decode_registration(data)
        self.assertEqual(result["genericClasses"],{"count":7,"pointerVa":"0x140000000"})
        self.assertEqual(result["fieldOffsets"]["count"],12)
        self.assertEqual(result["typeDefinitionsSizes"]["count"],13)
        with self.assertRaisesRegex(ValueError,"seven"):
            mod.decode_registration(data[:-1])

    def test_generic_index_above_registered_range_stays_unknown(self):
        class Unused:
            pass
        result=mod.generic_index_probe(Unused(),{
            "genericClasses":{"count":2,"pointerVa":"0x140000000"}},20)
        self.assertFalse(result["indexWithinRegisteredCount"])
        self.assertFalse(result["genericClassTypeIdentityProven"])


if __name__=="__main__":
    unittest.main()
