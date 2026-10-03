from __future__ import annotations

import unittest

from genshinre.scenehandlers import (
    decode_scene_handler_slot_load,
    scan_scene_handler_slot_loads,
)


class SceneHandlerSlotDecoderTests(unittest.TestCase):
    def test_decodes_verified_rax_slot_load(self) -> None:
        code = bytes.fromhex("488b88902a4b00")
        row = decode_scene_handler_slot_load(code, 0, 0xF0457D6)

        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual("rcx", row["destination_register"])
        self.assertEqual("rax", row["base_register"])
        self.assertEqual(0x4B2A90, row["slot_displacement"])
        self.assertEqual(0xF0457D6, row["instruction_rva"])
        self.assertEqual("488b88902a4b00", row["instruction_hex"])

    def test_decodes_verified_rcx_slot_load(self) -> None:
        code = bytes.fromhex("488b89b02a4b00")
        row = decode_scene_handler_slot_load(code, 0, 0x1000)

        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual("rcx", row["base_register"])
        self.assertEqual(0x4B2AB0, row["slot_displacement"])

    def test_rejects_sib_and_non_rcx_destination(self) -> None:
        sib = bytes.fromhex("488b8c24902a4b00")
        self.assertIsNone(decode_scene_handler_slot_load(sib, 0, 0x1000))

        rdx_destination = bytes.fromhex("488b90902a4b00")
        self.assertIsNone(
            decode_scene_handler_slot_load(rdx_destination, 0, 0x1000)
        )

    def test_scan_applies_half_open_range_and_alignment(self) -> None:
        code = b"\x90" + bytes.fromhex("488b88882a4b00")
        code += b"\x90" + bytes.fromhex("488b88902a4b00")
        code += b"\x90" + bytes.fromhex("488b88942a4b00")
        code += b"\x90" + bytes.fromhex("488b88b02a4b00")

        rows = scan_scene_handler_slot_loads(
            code,
            base_rva=0x2000,
            slot_start=0x4B2A88,
            slot_end=0x4B2AB0,
            slot_alignment=8,
        )

        self.assertEqual([0x4B2A88, 0x4B2A90], [r["slot_displacement"] for r in rows])
        self.assertEqual([0x2001, 0x2009], [r["instruction_rva"] for r in rows])

    def test_scan_rejects_invalid_contract(self) -> None:
        with self.assertRaises(ValueError):
            scan_scene_handler_slot_loads(
                b"",
                base_rva=0,
                slot_start=1,
                slot_end=1,
            )
        with self.assertRaises(ValueError):
            scan_scene_handler_slot_loads(
                b"",
                base_rva=0,
                slot_start=0,
                slot_end=1,
                slot_alignment=0,
            )


if __name__ == "__main__":
    unittest.main()
