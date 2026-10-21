"""Lock original 7.1 scene manager generic-inst field provenance without guessing row types."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

from genshinre.nativeprofile import PROFILE_71

EVIDENCE = (Path(__file__).resolve().parents[1] /
    "versions/7.1.0-global/analyses/progression/economy" /
    "7.1-chest-scene-manager-generic-type-evidence.json")


class TestOriginalSceneManagerGenericEvidence71(unittest.TestCase):
    def test_exact_original_native_type_entries(self):
        e = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        self.assertEqual(e["source"]["originalExecutableSha256"], PROFILE_71.exe_sha256)
        self.assertIn("ROW_VTABLE_UNRESOLVED", e["status"])
        cases = {
            "SceneTagConfigData": (84296, 666588, "815c0300000000001100150000000000", "0x35C81"),
            "SceneExcelConfigData": (35441, 545412, "c38a0200000000001100150000000000", "0x28AC3"),
        }
        for name, (owner, field_index, entry_bytes, raw_word) in cases.items():
            with self.subTest(name=name):
                obj = e["observations"][name]
                self.assertEqual(obj["originalManagerTypeDefinitionIndex"], owner)
                generic, boolean = obj["fields"]
                self.assertEqual(generic["fieldTypeIndex"], field_index)
                self.assertEqual(generic["nativeTypeKind"], 0x15)
                self.assertEqual(generic["nativeTypeEntryHex"], entry_bytes)
                self.assertEqual(generic["rawDataLow32"], raw_word)
                self.assertFalse(generic["candidateIl2CppGenericClassVaFileBacked"])
                self.assertEqual(int(generic["rawDataLow32"], 16),
                                 int.from_bytes(bytes.fromhex(entry_bytes)[:4], "little"))
                self.assertLess(int(generic["rawDataLow32"], 16), 0x140000000)
                self.assertEqual(boolean["fieldTypeIndex"], 439094)
                self.assertEqual(boolean["nativeTypeKind"], 2)
        self.assertEqual(e["interpretation"]["confirmedManagedGenericArgumentTypes"], [])
        self.assertEqual(e["interpretation"]["confirmedConcreteSceneRowTypeDefinitionIndices"], [])
        self.assertEqual(e["interpretation"]["rowReaderVirtualSlot"], "0xF0")
        self.assertTrue(any("drop_tag" in s for s in e["limitations"]))


if __name__ == "__main__":
    unittest.main()
