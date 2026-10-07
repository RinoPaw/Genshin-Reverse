from __future__ import annotations

import struct
import unittest

from genshinre.questguide71 import (
    MASK_XOR,
    STRING0_BLOCK_ADD,
    STRING0_LENGTH_XOR,
    STRING1_BLOCK_ADD,
    STRING1_LENGTH_XOR,
    parse_questguide71,
)


def u32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def encode_additive_blocks(decoded: bytes, add_key: int) -> bytes:
    out = bytearray()
    for pos in range(0, len(decoded), 8):
        block = decoded[pos:pos + 8]
        width = len(block)
        mask = (1 << (width * 8)) - 1
        value = int.from_bytes(block, "little")
        encoded = (value - (add_key & mask)) & mask
        out += encoded.to_bytes(width, "little")
    return bytes(out)


def encode_string(value: str, length_xor: int, block_add: int) -> bytes:
    raw = value.encode("utf-8")
    return (
        struct.pack("<H", len(raw) ^ length_xor)
        + encode_additive_blocks(raw, block_add)
    )


class QuestGuide71Tests(unittest.TestCase):
    def test_decodes_correlated_obfuscated_fields(self) -> None:
        # Presence rules:
        # - GCPCNAONCCJ uses decoded-mask bit 6, so flip raw bit 6 from MASK_XOR.
        # - CPHABDHIDKC/HBCFHMLPNDB/MIEPHKGCBKC/AEJMPEBJIHE/OEPAPDEPHDO
        #   use raw bits 29/31/25/19/18 respectively.
        mask_raw = MASK_XOR ^ (1 << 6)
        for bit in (29, 31, 25, 19, 18):
            mask_raw |= 1 << bit

        gcpcnaonccj = "[3_16627:1.000,2.000,3.000]"
        hbcfhmlpndb = "MarkSnezThespiaQuestResident"
        cphabdhidkc = 0x10203040
        miephkgcbkc = 0x55667788
        aejmpebjihe = 0x11223344
        oepapdephdo = 0xAABBCCDD

        payload = bytearray(u32(mask_raw))
        payload += encode_string(
            gcpcnaonccj, STRING0_LENGTH_XOR, STRING0_BLOCK_ADD
        )
        payload += u32(cphabdhidkc - 0x9A458AD0)
        payload += encode_string(
            hbcfhmlpndb, STRING1_LENGTH_XOR, STRING1_BLOCK_ADD
        )
        payload += u32(miephkgcbkc ^ 0x50426272)
        payload += u32(aejmpebjihe ^ 0x46B407FE)
        payload += u32(oepapdephdo ^ 0x135FBF6F)

        guide = parse_questguide71(bytes(payload), 0, len(payload))

        self.assertEqual(gcpcnaonccj, guide.gcpcnaonccj)
        self.assertEqual(hbcfhmlpndb, guide.hbcfhmlpndb)
        self.assertEqual(cphabdhidkc, guide.cphabdhidkc)
        self.assertEqual(miephkgcbkc, guide.miephkgcbkc)
        self.assertEqual(aejmpebjihe, guide.aejmpebjihe)
        self.assertEqual(oepapdephdo, guide.oepapdephdo)

        # Earlier structural-only names remain read-only aliases.
        self.assertEqual(gcpcnaonccj, guide.unknown_string_10)
        self.assertEqual(hbcfhmlpndb, guide.unknown_string_20)
        self.assertEqual(cphabdhidkc, guide.unknown_scalar_44)
        self.assertEqual(miephkgcbkc, guide.unknown_scalar_40)
        self.assertEqual(aejmpebjihe, guide.unknown_scalar_5c)
        self.assertEqual(oepapdephdo, guide.unknown_scalar_2c)


if __name__ == "__main__":
    unittest.main()
