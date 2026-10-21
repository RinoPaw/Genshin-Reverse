"""Original Global 7.1 SceneExcel/SceneTag metadata identity boundary guards."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
REPORT=(ROOT/"versions/7.1.0-global/analyses/progression/economy"/
        "7.1-chest-scene-native-row-reader-metadata-boundary.json")


class TestSceneNativeMetadataBoundary71(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=json.loads(REPORT.read_text(encoding="utf-8"))

    def test_original_loader_methods_and_class_indices(self):
        meta=self.data["loaderOwners"]
        self.assertEqual({
            name:(d["typeDefinitionIndex"],d["methodIndex"],d["methodRva"])
            for name,d in meta.items()
        },{
            "SceneTag":(84296,696653,"0x14015460"),
            "SceneExcel":(35441,279989,"0xA6C7000"),
        })
        for owner in meta.values():
            self.assertEqual(owner["typeFieldCount"],2)
            self.assertEqual(owner["typeMethodCount"],6)
            self.assertEqual(owner["fieldNames"],["PAAGPEHCJFI","PBLMHNBIAJL"])
            self.assertEqual(owner["rowVirtualReaderOffset"],"0xF0")
            self.assertEqual(owner["readerParameterType"],"FNIAHJGHFAK")
        self.assertEqual(meta["SceneTag"]["rowKeyMemoryOffset"],"0x28")
        self.assertEqual(meta["SceneExcel"]["rowKeyMemoryOffset"],"0x50")

    def test_virtual_row_reader_stays_unassigned(self):
        names=self.data["methodNameCollision"]
        self.assertEqual(names["methodOccurrencesWithRva"],12277)
        self.assertEqual(names["distinctOwnerTypeNames"],10867)
        self.assertEqual(names["sameLoaderParameterSignatureOccurrences"],10760)
        self.assertTrue(names["methodsWithSameNameAreUnverifiedCandidates"])
        self.assertEqual(names["relatedPinnedGadgetRowReader"]["methodIndex"],483590)
        self.assertEqual(names["relatedPinnedInheritedReader"]["methodIndex"],395933)
        self.assertEqual(self.data["provenance"]["methodMetadataGitBlob"],
                         "a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a")
        self.assertIn("VIRTUAL_ROW_OWNER_UNRESOLVED",self.data["status"])
        self.assertTrue(any("drop_tag" in x for x in self.data["limitations"]))


if __name__=="__main__":
    unittest.main()
