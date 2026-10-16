from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "audit-7.1-legacy-chest-sources.py"


class HistoricalChestSourcesTest(unittest.TestCase):
    def test_audit_external_resources_without_modifying_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "resources"
            (root / "ExcelBinOutput").mkdir(parents=True)
            (root / "Server").mkdir()
            (root / "Scripts/Scene/3").mkdir(parents=True)
            (root / "ExcelBinOutput/CityConfigData.json").write_text(
                json.dumps([{"cityId": 1, "areaIdVec": [1]}]), encoding="utf-8"
            )
            (root / "ExcelBinOutput/GadgetExcelConfigData.json").write_text(
                json.dumps([{"id": 100, "jsonName": "SceneObj_Chest_Default_Lv1"}]),
                encoding="utf-8",
            )
            (root / "Scripts/Scene/3/scene3_group1.lua").write_text(
                'gadgets = {\n'
                '  { config_id = 1, gadget_id = 100, area_id = 1, '
                'drop_tag = "战斗低级蒙德", chest_drop_id = 51010000 },\n'
                '}\n',
                encoding="utf-8",
            )
            (root / "Server/DropTableExcelConfigData.json").write_text(
                json.dumps([
                    {"id": 51010000, "dropVec": [{"itemId": 202, "countRange": "1", "weight": 1}]},
                    {"id": 52010000, "dropVec": [{"itemId": 203, "countRange": "1", "weight": 1}]},
                ]),
                encoding="utf-8",
            )
            (root / "Server/DropSubTableExcelConfigData.json").write_text(
                "[]", encoding="utf-8"
            )
            roots = Path(tmp) / "roots.json"
            roots.write_text(
                json.dumps([
                    {"tag": "战斗低级蒙德", "level": 1, "root": 51010000},
                    {"tag": "解谜低级蒙德", "level": 1, "root": 52010000},
                ]),
                encoding="utf-8",
            )
            out = Path(tmp) / "report.json"
            subprocess.run(
                [
                    sys.executable, str(SCRIPT),
                    "--resource-root", str(root),
                    "--roots", str(roots),
                    "--output", str(out),
                ], check=True, text=True, capture_output=True
            )
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(1, data["pairStats"]["total"])
            self.assertEqual(1, data["pairStats"]["different"])
            self.assertEqual(1, data["nativeGraphSummary"]["explicitSourceIdWithNonemptyTable"])
            self.assertEqual(
                {"DropTable": 2, "DropSubTable": 0}, data["nativeGraphSummary"]["fileRows"]
            )
            self.assertFalse((root / "audit-results").exists())


if __name__ == "__main__":
    unittest.main()
