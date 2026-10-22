"""Original Global 7.1 Gadget byte search negative result bounded by a positive native decoder."""
from importlib import util
from pathlib import Path
import json
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=util.spec_from_file_location("original_gadget_byte_boundary",ROOT/"scripts/audit-7.1-native-gadget-byte-search-boundary.py")
m=util.module_from_spec(spec);spec.loader.exec_module(m)

class OriginalGadgetNativeByteSearchBoundary(unittest.TestCase):
    def test_original_native_source_and_negative_scope(self):
        report=json.loads((ROOT/"versions/7.1.0-global/analyses/progression/economy/7.1-original-client-gadget-id-byte-search-boundary.json").read_text(encoding="utf-8"))
        self.assertEqual(report["artifacts"]["worldArea"]["jsonSha256"],m.WORLD_JSON_SHA)
        self.assertEqual(report["artifacts"]["knownOriginalGadgetExcel"]["jsonSha256"],m.GADGET_JSON_SHA)
        self.assertEqual(report["originalDecodedPositiveControls"]["authenticatedNativeChestGadgetRows"],20)
        self.assertEqual(report["originalDecodedPositiveControls"]["totalGadgetExcelRowsDecoded"],30599)
        self.assertEqual(len(report["originalDecodedPositiveControls"]["rows"]),20)
        self.assertEqual(report["worldAreaByteScan"]["individualMiHoYoBinDataExports"],167673)
        self.assertEqual(report["worldAreaByteScan"]["nativeIdDirectLe32Matches"],0)
        self.assertEqual(report["originalGadgetExcelPositiveDecodeByteScan"]["nativeIdDirectLe32Matches"],0)
        self.assertTrue(report["evidenceConclusion"]["nativeGadgetDefinitionsExistYetNoDirectRawLe32Bytes"])
        self.assertTrue(report["evidenceConclusion"]["nextInvestigationMustUseNativeDeserializerOrFieldDecoder"])
        self.assertFalse(report["evidenceConclusion"]["originalSceneInstanceLevelProven"])

    def test_unknown_original_artifacts_do_not_pass(self):
        with self.assertRaisesRegex(ValueError,"WorldArea scan artifact"):
            m.verify(b"wrong",b"wrong")
if __name__=="__main__":unittest.main()
