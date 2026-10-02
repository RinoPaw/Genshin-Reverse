from __future__ import annotations

import unittest

from genshinre.pointerxref import scan_pointer_holders


class PointerHolderTests(unittest.TestCase):
    def test_finds_absolute_aligned_qword_pointer(self) -> None:
        image_base = 0x140000000
        section_rva = 0x2004
        data = bytearray(32)
        data[0:8] = (image_base + 0x3008).to_bytes(8, "little")
        data[4:12] = (image_base + 0x3010).to_bytes(8, "little")
        data[12:20] = (image_base + 0x4000).to_bytes(8, "little")

        rows = scan_pointer_holders(
            bytes(data),
            section_rva=section_rva,
            image_base=image_base,
            target_start_rva=0x3000,
            target_end_rva=0x3020,
        )

        self.assertEqual(1, len(rows))
        self.assertEqual(0x2008, rows[0]["holder_rva"])
        self.assertEqual(0x3010, rows[0]["target_rva"])

    def test_target_end_is_exclusive(self) -> None:
        image_base = 0x140000000
        data = (image_base + 0x3020).to_bytes(8, "little")
        rows = scan_pointer_holders(
            data,
            section_rva=0x2000,
            image_base=image_base,
            target_start_rva=0x3000,
            target_end_rva=0x3020,
        )
        self.assertEqual([], rows)

    def test_rejects_invalid_range_and_alignment(self) -> None:
        with self.assertRaises(ValueError):
            scan_pointer_holders(
                b"\0" * 8,
                section_rva=0,
                image_base=0,
                target_start_rva=1,
                target_end_rva=1,
            )
        with self.assertRaises(ValueError):
            scan_pointer_holders(
                b"\0" * 8,
                section_rva=0,
                image_base=0,
                target_start_rva=0,
                target_end_rva=1,
                alignment=0,
            )


if __name__ == "__main__":
    unittest.main()
