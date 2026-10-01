from __future__ import annotations

import unittest
from dataclasses import dataclass

from genshinre.registrylayout import infer_layout_candidates


@dataclass(frozen=True)
class FakeSection:
    name: str
    virtual_address: int
    raw_size: int
    virtual_size: int


class FakeImage:
    image_base = 0x140000000

    def __init__(self, blob: bytes, base_rva: int = 0x1000):
        self.blob = blob
        self.base_rva = base_rva
        self.sections = [
            FakeSection(
                name=".rdata",
                virtual_address=base_rva,
                raw_size=len(blob),
                virtual_size=len(blob),
            )
        ]

    def read_rva(self, rva: int, size: int) -> bytes:
        offset = rva - self.base_rva
        if offset < 0 or offset >= len(self.blob):
            return b""
        return self.blob[offset : min(offset + size, len(self.blob))]

    def rva_to_offset(self, rva: int) -> int | None:
        offset = rva - self.base_rva
        return offset if 0 <= offset < len(self.blob) else None


class RegistryLayoutTests(unittest.TestCase):
    def test_recovers_stride_slot_and_direction_fields(self) -> None:
        row_count = 4896
        stride = 16
        base = 0x1000
        blob = bytearray(row_count * stride)

        for index in range(row_count):
            cmd = 1000 + index
            off = index * stride
            blob[off : off + 4] = cmd.to_bytes(4, "little")
            # Unrelated per-row field keeps the layout realistic enough to ensure
            # the probe must use the preserved slot/flag anchors.
            blob[off + 12 : off + 16] = (0xA0000000 + index).to_bytes(4, "little")

        def patch(index: int, cmd: int, slot: int, flag: int) -> None:
            off = index * stride
            blob[off : off + 4] = cmd.to_bytes(4, "little")
            blob[off + 4 : off + 8] = slot.to_bytes(4, "little")
            blob[off + 8] = flag

        patch(2232, 9369, 0x057E6498, 1)
        patch(3118, 22899, 0x057F6F60, 0)

        image = FakeImage(bytes(blob), base)
        candidates = infer_layout_candidates(image, min_stride=8, max_stride=24)
        strong = [row for row in candidates if row["status"] == "strong-layout-candidate"]

        self.assertTrue(strong)
        # A uint16 read and a uint32 read can both explain this synthetic fixture
        # because every CmdId fits in 16 bits and the following bytes are zero.
        # Preserve that ambiguity; assert that the expected uint32 interpretation
        # exists and carries the correct structural fields.
        matching = [
            row
            for row in strong
            if row["stride"] == 16
            and row["cmd_width"] == 4
            and row["anchor_22899_index_interpretation"] == 3118
            and row["cmd_column_base_rva"] == "0x1000"
        ]
        self.assertTrue(matching)
        best = matching[0]
        self.assertTrue(
            any(
                match["relative_to_cmd"] == 4 and match["encoding"] == "rva32"
                for match in best["slot_field_matches"]
            )
        )
        self.assertTrue(
            any(
                match["relative_to_cmd"] == 8 and match["width"] == 1
                for match in best["flag_field_matches"]
            )
        )
        self.assertEqual(row_count, best["column_metrics"]["readable_rows"])

    def test_cmd_spacing_without_slots_stays_weak(self) -> None:
        row_count = 4896
        stride = 12
        blob = bytearray(row_count * stride)
        for index in range(row_count):
            off = index * stride
            blob[off : off + 4] = (2000 + index).to_bytes(4, "little")

        blob[2232 * stride : 2232 * stride + 4] = (9369).to_bytes(4, "little")
        blob[3118 * stride : 3118 * stride + 4] = (22899).to_bytes(4, "little")

        candidates = infer_layout_candidates(FakeImage(bytes(blob)), min_stride=12, max_stride=12)
        matching = [row for row in candidates if row["stride"] == 12 and row["cmd_width"] == 4]
        self.assertTrue(matching)
        self.assertTrue(all(row["status"] == "cmd-spacing-candidate" for row in matching))
        self.assertTrue(all(not row["slot_field_matches"] for row in matching))


if __name__ == "__main__":
    unittest.main()
