from __future__ import annotations

import unittest

from genshinre.xrefs import decode_simple_rip_relative


class RipRelativeTests(unittest.TestCase):
    def test_known_registry_store_shape(self) -> None:
        instruction_rva = 0x07F852AB
        target_rva = 0x057E6498
        length = 7
        displacement = target_rva - (instruction_rva + length)
        code = b"\x48\x89\x05" + int(displacement).to_bytes(4, "little", signed=True)
        decoded = decode_simple_rip_relative(code, 0, instruction_rva)
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(target_rva, decoded["target_rva"])
        self.assertEqual("write", decoded["access"])
        self.assertEqual("mov", decoded["mnemonic"])

    def test_read_and_lea(self) -> None:
        for opcode, access in ((0x8B, "read"), (0x8D, "address")):
            instruction_rva = 0x1000
            target_rva = 0x2345
            displacement = target_rva - (instruction_rva + 7)
            code = bytes([0x48, opcode, 0x0D]) + displacement.to_bytes(4, "little", signed=True)
            decoded = decode_simple_rip_relative(code, 0, instruction_rva)
            self.assertIsNotNone(decoded)
            assert decoded is not None
            self.assertEqual(target_rva, decoded["target_rva"])
            self.assertEqual(access, decoded["access"])

    def test_rejects_non_rip_modrm(self) -> None:
        self.assertIsNone(decode_simple_rip_relative(bytes.fromhex("488B0111223344"), 0, 0x1000))


if __name__ == "__main__":
    unittest.main()
