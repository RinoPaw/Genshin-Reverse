"""Source-bound synthetic checks for 20 original 7.1 Gadget chest prefab controls."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import struct
import unittest

from genshinre.gadgetbin import GadgetRow, GadgetTableScan

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/audit-7.1-chest-prefab-controls.py"
spec = importlib.util.spec_from_file_location("chest_prefab_controls_71", SCRIPT)
prefabs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prefabs)


def fake_table():
    payload = bytearray(b"HEAD")
    rows = []
    for level in range(1, 6):
        for i, variant in enumerate(prefabs.KINDS, 1):
            id_ = 70210000 + 10 * level + i
            name = f"SceneObj_Chest_{variant}_Lv{level}"
            start = len(payload)
            payload.extend(b"\x91\xab" + b"\x11" * 16 + struct.pack("<I", id_))
            inner = len(payload)
            payload.extend(bytes(8))
            fields = {
                0x58: name, 0x6C: 26, 0x50: prefabs.ICON, 0x84: 2,
                0x78: True, 0x7D: True, 0x7E: True,
            }
            if level == 1:
                fields[0x48] = ["item"]
            rows.append(GadgetRow(
                id_, start, inner, inner, len(payload), 0x17, 0,
                {0x30: id_}, fields, {0x30: (inner - 4, inner)}, {}))
    return GadgetTableScan("48454144", 20, tuple(rows), len(payload),
                           22 * 20), bytes(payload)


class TestChestPrefabControls71(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = json.loads(prefabs.OUTPUT.read_text(encoding="utf-8"))

    def test_synthetic_exact_20_name_and_field_controls(self):
        scan, raw = fake_table()
        self.assertEqual(prefabs.controls(scan, raw), self.expected)
        self.assertEqual(self.expected["controls"]["verifiedGadgetDefinitionCount"], 20)
        self.assertEqual(self.expected["controls"]["literalNameSuffixLevels"],
                         [1, 2, 3, 4, 5])
        self.assertEqual(self.expected["controls"]["offset0x48List"],
                         {"presentWithExactlyItem": 4, "absentOnWire": 16})
        self.assertNotIn("chestGrade", self.expected)

    def test_renamed_level_missing_field_and_wrong_list_fail_closed(self):
        scan, raw = fake_table()
        changed = copy.deepcopy(scan)
        changed.rows[4].fields[0x58] = "SceneObj_Chest_Default_Lv1"
        with self.assertRaisesRegex(ValueError, "original prefab fields differ"):
            prefabs.controls(changed, raw)
        changed = copy.deepcopy(scan)
        del changed.rows[0].fields[0x48]
        with self.assertRaisesRegex(ValueError, "list-presence"):
            prefabs.controls(changed, raw)
        changed = copy.deepcopy(scan)
        changed.rows[5].fields[0x48] = []
        with self.assertRaisesRegex(ValueError, "list-presence"):
            prefabs.controls(changed, raw)

    def test_wrong_control_prefix_and_source_rejected(self):
        scan, raw = fake_table()
        modified = bytearray(raw)
        modified[4] = 0
        with self.assertRaisesRegex(ValueError, "outer prefix differs"):
            prefabs.controls(scan, bytes(modified))
        with self.assertRaisesRegex(ValueError, "SHA-256/size"):
            prefabs.audit(b"wrong original raw bytes")


if __name__ == "__main__":
    unittest.main()
