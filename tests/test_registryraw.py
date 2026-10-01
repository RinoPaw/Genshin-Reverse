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
    def _candidate(self, *, cmd_width: int = 4, base: str = "0x1000") -> dict[str, object]:
        return {
            "status": "strong-layout-candidate",
            "stride": 16,
            "cmd_width": cmd_width,
            "cmd_column_base_rva": base,
            "anchor_22899_index_interpretation": 3118,
            "anchor_9369_cmd_rva": "0x9B80",
            "anchor_22899_cmd_rva": "0xD2E0",
            "slot_field_matches": [
                {"relative_to_cmd": 4, "encoding": "rva32", "width": 4}
            ],
            "flag_field_matches": [
                {"relative_to_cmd": 8, "width": 4},
                {"relative_to_cmd": 8, "width": 1},
                {"relative_to_cmd": 8, "width": 2},
            ],
            "column_metrics": {
                "readable_rows": 4896,
                "nonzero_rows": 4896,
                "protocol_range_rows": 4896,
                "unique_nonzero_values": 4896,
            },
        }

    def test_choose_layout_collapses_zero_extended_flag_widths(self) -> None:
        selected = choose_closed_layout({"candidates": [self._candidate()]})
        self.assertEqual(1, selected["selected_flag_field"]["width"])
        self.assertEqual("rva32", selected["selected_slot_field"]["encoding"])

    def test_choose_layout_collapses_equivalent_cmd_width_aliases(self) -> None:
        selected = choose_closed_layout(
            {"candidates": [self._candidate(cmd_width=2), self._candidate(cmd_width=4)]}
        )
        self.assertEqual(4, selected["cmd_width"])
        self.assertEqual([2, 4], selected["cmd_width_aliases"])

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

        probe = {"candidates": [self._candidate(cmd_width=4)]}

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
            self.assertEqual([4], summary["layout"]["cmd_width_aliases"])

            with output.open("r", encoding="utf-8", newline="") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual("9369", rows[2232]["cmd_id"])
            self.assertEqual("1", rows[2232]["registry_flag"])
            self.assertEqual("0x57E6498", rows[2232]["type_slot_rva"])
            self.assertEqual("22899", rows[3118]["cmd_id"])
            self.assertEqual("0", rows[3118]["registry_flag"])
            self.assertEqual("0x57F6F60", rows[3118]["type_slot_rva"])

    def test_rejects_distinct_closed_layouts(self) -> None:
        first = self._candidate(base="0x1000")
        second = self._candidate(base="0x2000")
        with self.assertRaises(ValueError):
            choose_closed_layout({"candidates": [first, second]})

    def test_does_not_merge_widths_with_different_column_metrics(self) -> None:
        narrow = self._candidate(cmd_width=2)
        wide = self._candidate(cmd_width=4)
        wide["column_metrics"] = {
            "readable_rows": 4896,
            "nonzero_rows": 4896,
            "protocol_range_rows": 4000,
            "unique_nonzero_values": 4896,
        }
        with self.assertRaises(ValueError):
            choose_closed_layout({"candidates": [narrow, wide]})


if __name__ == "__main__":
    unittest.main()
