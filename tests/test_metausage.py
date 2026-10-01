from __future__ import annotations

import unittest

from genshinre.metausage import probe_table_entry
from genshinre.pe import PESection


class FakeImage:
    image_base = 0x140000000

    def __init__(self) -> None:
        self.sections = [PESection(".data", 0x5000000, 0x1000000, 0, 0x1000000, 0xC0000040)]
        self._memory: dict[int, bytes] = {}

    def put_qword(self, rva: int, value: int) -> None:
        self._memory[rva] = value.to_bytes(8, "little")

    def read_rva(self, rva: int, size: int) -> bytes:
        value = self._memory.get(rva, b"")
        return value[:size]

    def rva_to_offset(self, rva: int) -> int | None:
        if 0x5000000 <= rva < 0x6000000:
            return rva
        return None


class MetadataUsageTests(unittest.TestCase):
    def test_preserved_9369_usage_anchor(self) -> None:
        image = FakeImage()
        table_rva = 0x5100000
        table_va = image.image_base + table_rva
        index = 37523
        slot_rva = 0x057E6498
        image.put_qword(table_rva + index * 8, image.image_base + slot_rva)
        probe = probe_table_entry(image, 40000, table_va, index, slot_rva)
        self.assertTrue(probe["readable"])
        self.assertTrue(probe["entry_mapped"])
        self.assertTrue(probe["matches_expected_slot"])
        self.assertEqual(f"0x{slot_rva:X}", probe["entry_rva"])

    def test_out_of_range_index(self) -> None:
        image = FakeImage()
        probe = probe_table_entry(image, 10, image.image_base + 0x5100000, 37523, 0x057E6498)
        self.assertFalse(probe["readable"])
        self.assertFalse(probe["matches_expected_slot"])


if __name__ == "__main__":
    unittest.main()
