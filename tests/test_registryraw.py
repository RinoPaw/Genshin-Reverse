from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from genshinre.registryraw import choose_closed_layout, export_raw_registry_71


class FakeImage:
    image_base = 0x140000000

    def __init__(self, _path: Path, blob: bytes):
        self.blob = blob
        self.base = 0x1000

    def read_rva(self, rva: int, size: int) -> bytes:
        offset = rva - self.base
        if offset < 0 or offset >= len(self.blob):
            return b""
        return self.blob[offset : min(offset + size, len(self.blob))]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None


class RegistryRawTests(unittest.TestCase):
    def test_choose_layout_collapses_zero_extended_flag_widths(self) -> None:
        probe = {
            "candidates": [
                {
                    "status": "strong-layout-candidate",
                    "stride": 16,
                    "cmd_width": 4,
                    "cmd_column_base_rva": "0x1000",
                    "anchor_22899_index_interpretation": 3118,
                    "slot_field_matches": [
                        {"relative_to_cmd": 4, "encoding": "rva32", "width": 4}
                    ],
                    "flag_field_matches": [
                        {"relative_to_cmd": 8, "width": 4},
                        {"relative_to_cmd": 8, "width": 1},
                        {"relative_to_cmd": 8, "width": 2},
                    ],
                }
            ]
        }
        selected = choose_closed_layout(probe)
        self.assertEqual(1, selected["selected_flag_field"]["width"])
        self.assertEqual("rva32", selected["selected_slot_field"]["encoding"])

    def test_export_preserves_native_rows_and_anchors(self) -> None:
        row_count = 4896
        stride = 16
        blob = bytearray(row_count * stride)
        for index in range(row_count):
            off = index * stride
            cmd_id = 1000 + index
            blob[off : off + 4] = cmd_id.to_bytes(4, "little")
            blob[off + 4 : off + 8] = (0x05000000 + index * 8).to_bytes(4, "little")
            blob[off + 8] = index & 1

        def set_row(index: int, cmd_id: int, slot: int, flag: int) -> None:
            off = index * stride
            blob[off : off + 4] = cmd_id.to_bytes(4, "little")
            blob[off + 4 : off + 8] = slot.to_bytes(4, "little")
            blob[off + 8] = flag

        set_row(2232, 9369, 0x057E6498, 1)
        set_row(3118, 22899, 0x057F6F60, 0)

        probe = {
            "candidates": [
                {
                    "status": "strong-layout-candidate",
                    "stride": 16,
                    "cmd_width": 4,
                    "cmd_column_base_rva": "0x1000",
                    "anchor_22899_index_interpretation": 3118,
                    "slot_field_matches": [
                        {"relative_to_cmd": 4, "encoding": "rva32", "width": 4}
                    ],
                    "flag_field_matches": [
                        {"relative_to_cmd": 8, "width": 1}
                    ],
                }
            ]
        }

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            exe = root / "sample.exe"
            exe.write_bytes(b"synthetic")
            probe_path = root / "probe.json"
            probe_path.write_text(json.dumps(probe), encoding="utf-8")
            output = root / "raw.csv"
            summary_path = root / "raw.summary.json"

            class BoundFakeImage(FakeImage):
                def __init__(self, path: Path):
                    super().__init__(path, bytes(blob))

            with patch("genshinre.registryraw.PEImage", BoundFakeImage):
                summary = export_raw_registry_71(
                    exe,
                    probe_path,
                    output,
                    summary_json=summary_path,
                    allow_unknown_sample=True,
                )

            self.assertEqual(4896, summary["row_count"])
            self.assertEqual(4896, summary["unique_cmd_ids"])
            self.assertTrue(summary["all_anchor_checks_pass"])
            self.assertEqual(16, summary["layout"]["stride"])
            self.assertEqual(1, summary["layout"]["flag_field"]["width"])

            rows = list(csv.DictReader(output.open("r", encoding="utf-8", newline="")))
            self.assertEqual("9369", rows[2232]["cmd_id"])
            self.assertEqual("1", rows[2232]["registry_flag"])
            self.assertEqual("0x57E6498", rows[2232]["type_slot_rva"])
            self.assertEqual("22899", rows[3118]["cmd_id"])
            self.assertEqual("0", rows[3118]["registry_flag"])
            self.assertEqual("0x57F6F60", rows[3118]["type_slot_rva"])

    def test_rejects_multiple_closed_layouts(self) -> None:
        candidate = {
            "status": "strong-layout-candidate",
            "stride": 16,
            "cmd_width": 4,
            "cmd_column_base_rva": "0x1000",
            "anchor_22899_index_interpretation": 3118,
            "slot_field_matches": [{"relative_to_cmd": 4, "encoding": "rva32", "width": 4}],
            "flag_field_matches": [{"relative_to_cmd": 8, "width": 1}],
        }
        with self.assertRaises(ValueError):
            choose_closed_layout({"candidates": [candidate, dict(candidate)]})


if __name__ == "__main__":
    unittest.main()
