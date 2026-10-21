"""Source-bound 7.1 original scene index and two raw Excel asset evidence gates."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
ECON = ROOT / "versions/7.1.0-global/analyses/progression/economy"
INDEX = ECON / "7.1-chest-native-scene-index-hypotheses.json"
RAW = ECON / "7.1-chest-scene-native-excel-entrypoints.json"


def load_probe(filename: str, name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestOriginalSceneSourceProvenance71(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = json.loads(INDEX.read_text(encoding="utf-8"))
        cls.assets = json.loads(RAW.read_text(encoding="utf-8"))

    def test_exact_index_805_hypotheses_and_both_controls(self):
        script = load_probe("probe-7.1-chest-scene-index.py", "original_scene_index_71")
        report = self.index
        self.assertEqual(report["source"]["designIndexRawSha256"], script.INDEX_SHA256)
        names = [p for paths in script.candidates().values() for p in paths]
        self.assertEqual(len(names), 805)
        import hashlib
        self.assertEqual(report["candidatesSha256"],
                         hashlib.sha256((chr(10).join(names) + chr(10)).encode()).hexdigest())
        self.assertEqual(report["candidateCount"], 805)
        self.assertEqual(report["statusCounts"],
                         {"HASH_ABSENT": 802, "HASH_RESOLVED": 3})
        self.assertEqual(report["controls"]["known-Excel"]["status"], "HASH_RESOLVED")
        self.assertEqual(report["controls"]["known-scene-area"]["status"], "HASH_RESOLVED")
        self.assertEqual(report["groups"]["historical-group-name-hypotheses"],
                         {"hypothesesTested": 672, "statusCounts": {"HASH_ABSENT": 672},
                          "matchesOrAmbiguous": []})
        self.assertEqual(report["source"]["indexType"], "MiHoYoBinData only")

    def test_3_exact_client_paths_and_two_pinned_payloads(self):
        groups = self.index["groups"]
        hits = [*groups["scene-excel-config"]["matchesOrAmbiguous"],
                *groups["adjacent-scene-point-and-support-hypotheses"]["matchesOrAmbiguous"]]
        self.assertEqual({r["path"] for r in hits}, {
            "Data/_ExcelBinOutput/SceneExcelConfigData",
            "Data/_ExcelBinOutput/SceneTagConfigData",
            "Data/_BinOutput/Scene/Point/scene3_point",
        })
        self.assertEqual({r["blockId"] for r in hits}, {25539185, 24230448})
        entry = load_probe("audit-7.1-native-scene-entrypoints.py", "original_scene_assets_71")
        self.assertEqual(self.assets["indexRawExportSha256"], entry.INDEX_SHA256)
        self.assertEqual(self.assets["verifiedGadgetControlSha256"],
                         entry.CONTROL_GADGET_RAW_SHA256)
        self.assertEqual(len(self.assets["assets"]), 2)
        by_name = {a["candidateSourcePath"]: a for a in self.assets["assets"]}
        s = by_name["Data/_ExcelBinOutput/SceneExcelConfigData"]
        t = by_name["Data/_ExcelBinOutput/SceneTagConfigData"]
        self.assertEqual((s["rawExportBytes"], s["payloadBytes"]), (273356, 273352))
        self.assertEqual((t["rawExportBytes"], t["payloadBytes"]), (38948, 38941))
        self.assertEqual(s["payloadSha256"],
                         "588563f62149d62038c7ee3b179e50191ecc9a3cfc003353e18a831918d27f6a")
        self.assertEqual(t["payloadSha256"],
                         "9c043ecdbfba6a17c00243b37ae2bb3566ac9c09dcf800b648a76c3e113958ee")
        self.assertFalse(s["wholePayloadUtf8"])
        self.assertFalse(t["wholePayloadUtf8"])
        self.assertTrue(any("drop_tag" in x for x in self.assets["limitations"]))
        self.assertNotIn("dropTag", self.assets)
        self.assertNotIn("chestDropId", self.assets)

    def test_shared_report_identity_and_control_block(self):
        self.assertEqual(self.index["source"]["designIndexRawSha256"],
                         self.assets["indexRawExportSha256"])
        for a in self.assets["assets"]:
            self.assertEqual(a["sourceBlockGroupId"], 0)
            self.assertEqual(a["sourceBlockId"], 25539185)
            self.assertEqual(a["nameCollisionCount"], 1)
            self.assertEqual(len(a["payloadSha256"]), 64)
        self.assertIn("UNRESOLVED", self.index["status"])
        self.assertIn("FIELD_MEANING_UNKNOWN", self.assets["status"])


if __name__ == "__main__":
    unittest.main()
