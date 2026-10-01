from __future__ import annotations

import unittest

from genshinre.usage import (
    ANCHOR_9369,
    INITIALIZER_RVA_71,
    decode_mov_ecx_immediate,
    decode_rel32_call,
    iter_usage_call_records,
)


class UsageRecoveryTests(unittest.TestCase):
    def test_rel32_call(self) -> None:
        call_rva = 0x1000
        displacement = INITIALIZER_RVA_71 - (call_rva + 5)
        code = b"\xE8" + displacement.to_bytes(4, "little", signed=True)
        decoded = decode_rel32_call(code, 0, call_rva)
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(INITIALIZER_RVA_71, decoded["target_rva"])

    def test_mov_ecx_immediate_forms(self) -> None:
        value = ANCHOR_9369["usage_destination"]
        samples = [
            (b"\xB9" + value.to_bytes(4, "little"), "mov-ecx-imm32"),
            (b"\xC7\xC1" + value.to_bytes(4, "little"), "mov-ecx-imm32-c7"),
            (b"\x48\xC7\xC1" + value.to_bytes(4, "little"), "mov-rcx-imm32-c7"),
            (b"\x48\xB9" + value.to_bytes(8, "little"), "mov-rcx-imm64"),
        ]
        for code, pattern in samples:
            with self.subTest(pattern=pattern):
                decoded = decode_mov_ecx_immediate(code, 0, 0x2000)
                self.assertIsNotNone(decoded)
                assert decoded is not None
                self.assertEqual(value, decoded["value"])
                self.assertEqual(pattern, decoded["pattern"])

    def test_historical_9369_triplet_shape(self) -> None:
        # Synthetic instruction sequence shaped around the preserved historical store:
        # mov ecx,37523 ; call 0x523400 ; mov [rip+0x57E6498],rax
        store_rva = ANCHOR_9369["store_rva"]
        base_rva = store_rva - 10
        usage = ANCHOR_9369["usage_destination"]
        slot = ANCHOR_9369["type_slot_rva"]

        mov = b"\xB9" + usage.to_bytes(4, "little")
        call_rva = base_rva + len(mov)
        call_disp = INITIALIZER_RVA_71 - (call_rva + 5)
        call = b"\xE8" + call_disp.to_bytes(4, "little", signed=True)
        store_disp = slot - (store_rva + 7)
        store = b"\x48\x89\x05" + store_disp.to_bytes(4, "little", signed=True)
        code = mov + call + store + b"\x90" * 16

        records = list(iter_usage_call_records(code, base_rva, ".text"))
        self.assertEqual(1, len(records))
        row = records[0]
        self.assertEqual(usage, row["usage_destination"])
        self.assertEqual(f"0x{store_rva:X}", row["store_rva"])
        self.assertEqual(f"0x{slot:X}", row["type_slot_rva"])
        self.assertTrue(row["_has_usage"])
        self.assertTrue(row["_has_store"])


if __name__ == "__main__":
    unittest.main()
